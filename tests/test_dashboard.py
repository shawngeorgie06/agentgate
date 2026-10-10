import asyncio
import dataclasses
import json
from contextlib import asynccontextmanager

import httpx2 as httpx
import pytest
from fastmcp import Client

from broker.dashboard import create_dashboard
from broker.http_auth import create_token_file, read_token_file, token_verifier
from broker.mcp_server import build_mcp
from tests.test_gmail import make_tools, pending


@asynccontextmanager
async def dashboard(tmp_path):
    broker, service, gmail, tools = make_tools(tmp_path)
    path = tmp_path / 'agent-token'
    create_token_file(str(path))
    agent_token = read_token_file(str(path))
    mcp = build_mcp(broker, auth=token_verifier(str(path)), gmail_tools=tools)
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
