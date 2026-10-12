import asyncio
import dataclasses
import json
import os
from contextlib import asynccontextmanager

import httpx2 as httpx
import pytest
from fastmcp import Client

from broker.dashboard import create_dashboard
from broker.agent_registry import AgentRegistry
from broker.http_auth import create_token_file, read_token_file, token_verifier
from broker.mcp_server import build_mcp
from tests.test_gmail import make_tools, pending


@asynccontextmanager
async def dashboard(tmp_path):
    broker, service, gmail, tools = make_tools(tmp_path)
    path = tmp_path / 'agent-token'
    create_token_file(str(path))
    agent_token = read_token_file(str(path))
    mcp = build_mcp(broker, auth=token_verifier(str(path)), gmail_tools=tools, trusted_agent='local-agent')
    app = create_dashboard(mcp.http_app(path='/mcp'), broker, tools, 'operator-secret-credential')
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://127.0.0.1:8765', headers={'Authorization':'Bearer operator-secret-credential'}) as client:
            yield client, broker, service, tools, mcp, agent_token


@pytest.mark.asyncio
async def test_operator_auth_is_separate_and_host_origin_guards(tmp_path):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        assert (await client.get('/api/status', headers={'Authorization':''})).status_code == 401
        assert (await client.get('/api/status', headers={'Authorization':f'Bearer {agent_token}'})).status_code == 401
        assert (await client.get('/api/status', headers={'Origin':'https://foreign.example'})).status_code == 403
        assert (await client.get('/api/status', headers={'Host':'foreign.example'})).status_code == 421
        assert (await client.get('/api/status')).json()['ok']
        page = await client.get('/app')
        assert page.status_code == 200
        assert 'frame-ancestors' in page.headers['content-security-policy']
        assert 'operator-secret' not in page.text
        assert (await client.get('/app/secret.json')).status_code == 404
        assert (await client.get('/api/status')).headers['cache-control'] == 'no-store'


@pytest.mark.asyncio
@pytest.mark.parametrize('approve', [True, False])
async def test_app_resolves_agent_send_and_blocks_stale_approval(tmp_path, approve):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        # This is an agent's MCP call, not an app-only send implementation.
        async with Client(mcp) as agent:
            send = asyncio.create_task(agent.call_tool('gmail.send_draft', {'agent':'local-agent','draft_id':'draft-1'}))
            req = await pending(broker)
            status = (await client.get('/api/status')).json()['data']
            assert status['pending']['preview']['to'] == ['recipient@example.test']
            assert status['pending']['id'] == req.request_id
            assert (await client.post('/api/approval', json={'id':'stale-id','approved':True})).status_code == 409
            assert not send.done()
            # Approval credentials are never available to the MCP client.
            assert (await client.post('/api/approval', json={'id':req.request_id,'approved':True}, headers={'Authorization':f'Bearer {agent_token}'})).status_code == 401
            result = await client.post('/api/approval', json={'id':req.request_id,'approved':approve})
            assert result.json()['ok']
            assert (await send).data['ok'] is approve
            assert (await client.post('/api/approval', json={'id':req.request_id,'approved':True})).status_code == 409
            assert len([call for call in service.calls if call[1] == 'send']) == int(approve)


@pytest.mark.asyncio
async def test_app_send_timeout_and_operator_reads_drafts_activity(tmp_path):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        broker.config = dataclasses.replace(broker.config, escalation_timeout_seconds=0.05)
        assert (await client.get('/api/inbox')).json()['data']['messages'][0]['subject'] == 'Test subject'
        assert (await client.get('/api/read?id=message-1')).json()['data']['parts'][0]['content'] == 'Hello!\n'
        saved = await client.post('/api/draft', json={'to':'recipient@example.test','subject':'Subject','body':'Body'})
        assert saved.json()['data']['id'] == 'draft-1'
        assert not any(call[1] == 'send' for call in service.calls)
        sent = await client.post('/api/send', json={'draft_id':'draft-1'})
        assert not sent.json()['ok']
        assert not any(call[1] == 'send' for call in service.calls)
        assert (await client.get('/api/status')).json()['data']['pending'] is None
        activity = (await client.get('/api/activity')).json()['data']['activity']
        assert any(row['decision']=='expired' for row in activity)
        assert 'Body' not in json.dumps(activity)
        assert (await client.post('/api/approval', json={'approved':'yes'})).status_code == 409
        assert (await client.post('/api/draft', content='not json')).status_code == 400
        assert (await client.post('/api/draft', json={'body': []})).status_code == 400
        assert (await client.post('/api/draft', content='x'*262145)).status_code == 413


@pytest.mark.asyncio
async def test_owner_send_review_survives_revoked_bootstrap_identity(tmp_path):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        registry = AgentRegistry(str(tmp_path / 'dashboard-agents.sqlite3'))
        broker.agent_registry = registry
        bootstrap = registry.register('agentgate-local')
        assert registry.revoke('agentgate-local')

        owner_send = asyncio.create_task(client.post('/api/send', json={'draft_id':'draft-1'}))
        request = await pending(broker)
        assert request.agent == 'operator'
        assert request.credential == 'gmail:send'
        assert registry.authenticate(bootstrap['token']) is None

        approved = await client.post('/api/approval', json={'id':request.request_id,'approved':True})
        assert approved.json()['ok']
        response = await owner_send
        assert response.json()['ok']
        assert any(call[1] == 'send' for call in service.calls)
        activity = (await client.get('/api/activity')).json()['data']['activity']
        assert any(row['agent'] == 'operator' and row['credential_requested'] == 'gmail:send' for row in activity)
        assert bootstrap['token'] not in json.dumps(activity)


@pytest.mark.asyncio
async def test_policy_change_approval_exposes_complete_frozen_proposal(tmp_path):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        policy = {
            'name':'review-only', 'agent':'example-agent', 'credential':'gmail:read',
            'auto_approve':False, 'escalate':True,
        }
        async with Client(mcp) as agent:
            proposal = asyncio.create_task(agent.call_tool('policy.add', {'policy':policy, 'agent':'local-agent'}))
            request = await pending(broker)
            response = await client.get('/api/status')
            shown = response.json()['data']['pending']
            assert shown['id'] == request.request_id
            assert shown['credential'] == 'policy.add:review-only'
            assert shown['preview'] == policy
            assert shown['preview']['agent'] == 'example-agent'
            assert shown['preview']['credential'] == 'gmail:read'
            assert shown['preview']['auto_approve'] is False
            rejected = await client.post('/api/approval', json={'id':request.request_id,'approved':False})
            assert rejected.json()['ok']
            assert (await proposal).data['added'] is False


@pytest.mark.asyncio
async def test_draft_pagination_and_attempt_marker(tmp_path):
    from types import SimpleNamespace
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        calls = []
        def draft_list(**kwargs):
            calls.append(kwargs)
            return SimpleNamespace(execute=lambda: {'drafts':[{'id':'draft-1'}], 'nextPageToken':'older-drafts'})
        service.list = draft_list
        tools._sent_drafts.add('draft-1')
        page = (await client.get('/api/drafts?page_token=older-drafts')).json()['data']
        assert page['next_page_token'] == 'older-drafts'
        assert page['drafts'][0]['attempted'] is True
        assert calls == [{'userId':'me','maxResults':10,'pageToken':'older-drafts'}]


@pytest.mark.asyncio
async def test_agent_operator_routes_export_private_credential_and_revoke(tmp_path):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        registry = AgentRegistry(str(tmp_path / 'agents.sqlite3'))
        broker.agent_registry = registry
        created = await client.post('/api/agent-register', json={'name':'sample-helper','ttl_hours':24})
        assert created.status_code == 200
        data = created.json()['data']
        assert data['agent']['id'] == 'sample-helper'
        assert data['agent']['status'] == 'active'
        assert data['agent']['expires_at']
        assert 'token' not in created.json()['data']
        credential = open(data['credential_path'], encoding='ascii').read().strip()
        assert credential and credential not in created.text
        assert (tmp_path / 'agent-credentials').stat().st_mode & 0o777 == 0o700
        assert os.stat(data['credential_path']).st_mode & 0o777 == 0o600
        assert registry.authenticate(credential)['id'] == 'sample-helper'
        assert (await client.get('/api/agents', headers={'Authorization':f'Bearer {credential}'})).status_code == 401
        assert (await client.post('/api/agent-register', json={'name':'second-agent','ttl_hours':24}, headers={'Authorization':f'Bearer {credential}'})).status_code == 401
        assert (await client.post('/api/agent-revoke', json={'id':'sample-helper'}, headers={'Authorization':f'Bearer {credential}'})).status_code == 401
        listed = await client.get('/api/agents')
        assert listed.json()['data']['agents'][0]['id'] == 'sample-helper'
        assert credential not in open(broker.config.logs_path, encoding='utf-8').read()
        assert (await client.post('/api/agent-revoke', json={'id':'sample-helper'})).json()['data']['revoked']
        assert registry.authenticate(credential) is None
        assert registry.list_agents()[0]['status'] == 'revoked'
        assert (await client.get('/api/agents')).json()['data']['agents'][0]['status'] == 'revoked'


@pytest.mark.asyncio
@pytest.mark.parametrize('payload', [
    {'name':'../outside', 'ttl_hours':24},
    {'name':'invalid-name!', 'ttl_hours':24},
    {'name':'valid-name', 'ttl_hours':0},
    {'name':'valid-name', 'ttl_hours':8761},
    {'name':'valid-name', 'ttl_hours':1.5},
])
async def test_agent_registration_rejects_invalid_name_or_ttl(tmp_path, payload):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        broker.agent_registry = AgentRegistry(str(tmp_path / 'agents.sqlite3'))
        response = await client.post('/api/agent-register', json=payload)
        assert response.status_code == 400
        assert not broker.agent_registry.list_agents()


@pytest.mark.asyncio
async def test_agent_export_conflict_does_not_create_or_reissue_identity(tmp_path):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        broker.agent_registry = AgentRegistry(str(tmp_path / 'agents.sqlite3'))
        credential_dir = tmp_path / 'agent-credentials'
        credential_dir.mkdir(mode=0o700)
        credential_path = credential_dir / 'already-there.token'
        credential_path.write_text('keep-me', encoding='ascii')
        response = await client.post('/api/agent-register', json={'name':'already-there','ttl_hours':720})
        assert response.status_code == 409
        assert credential_path.read_text(encoding='ascii') == 'keep-me'
        assert broker.agent_registry.list_agents() == []


@pytest.mark.asyncio
async def test_agent_routes_report_unavailable_registry_safely(tmp_path):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        broker.agent_registry = None
        response = await client.get('/api/agents')
        assert response.status_code == 200
        assert response.json()['data'] == {'agents': [], 'available': False}
        register = await client.post('/api/agent-register', json={'name':'sample-helper','ttl_hours':720})
        assert register.status_code == 503
        assert 'Traceback' not in register.text
