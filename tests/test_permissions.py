import asyncio
import json

import pytest
import yaml

from broker.agent_registry import AgentRegistry
from broker.permissions import Permissions, PermissionConflict
from tests.test_gmail import make_tools, pending
from tests.test_dashboard import dashboard


def setup(tmp_path):
    broker, service, provider, tools = make_tools(tmp_path)
    broker.agent_registry = AgentRegistry(tmp_path/'agents.sqlite3')
    broker.agent_registry.register('local-agent')
    broker.agent_registry.register('other-agent')
    return broker, service, provider, tools, Permissions(broker)


def selections(read='allow', draft='deny', send='deny'):
    return {'gmail:read':read,'gmail:draft':draft,'gmail:send':send}


def test_saved_rules_persist_preserve_other_rules_and_detect_stale_edits(tmp_path):
    broker, _, _, _, permissions = setup(tmp_path)
    original = yaml.safe_load(open(broker.config.policies_path))['policies']
    view = permissions.view('local-agent')
    saved = permissions.save('local-agent', selections(), view['revision'])
    assert saved['permissions'] == selections()
    assert yaml.safe_load(open(broker.config.policies_path))['policies'][3:] == original
    assert broker.engine.evaluate('local-agent','gmail:read').auto_approve
    assert not broker.engine.evaluate('local-agent','gmail:draft').escalate
    with pytest.raises(PermissionConflict):
        permissions.save('other-agent', selections(), view['revision'])
    fresh = Permissions(broker).view('local-agent')
    permissions.save('local-agent', selections(draft='ask', send='ask'), fresh['revision'])
    assert len(yaml.safe_load(open(broker.config.policies_path))['policies']) == len(original)+3


@pytest.mark.parametrize('bad', [selections(send='allow'), {'gmail:read':'allow'}, selections(read=True), {**selections(),'credential:all':'allow'}])
def test_invalid_selections_never_modify_policy_file(tmp_path, bad):
    broker, _, _, _, permissions = setup(tmp_path)
    path = broker.config.policies_path
    before = open(path,'rb').read()
    with pytest.raises(ValueError):
        permissions.save('local-agent',bad,permissions.view('local-agent')['revision'])
    assert open(path,'rb').read() == before


@pytest.mark.asyncio
async def test_pending_send_cannot_survive_permission_change(tmp_path):
    broker, service, _, tools, permissions = setup(tmp_path)
    view=permissions.view('local-agent')
    permissions.save('local-agent',selections(draft='allow',send='ask'),view['revision'])
    send=asyncio.create_task(tools.send_draft('local-agent','draft-1'))
    request=await pending(broker)
    permissions.save('local-agent',selections(draft='allow',send='deny'),permissions.view('local-agent')['revision'])
    # Even a stale approval cannot turn the denied request back into a send.
    broker.approvals.resolve(request,True)
    assert not (await send)['ok']
    assert not any(call[1]=='send' for call in service.calls)
    assert broker.approvals.get_pending() is None


@pytest.mark.asyncio
async def test_provider_wait_cannot_bypass_new_ask_permission(tmp_path):
    broker, service, provider, tools, permissions = setup(tmp_path)
    permissions.save('local-agent',selections(draft='allow'),permissions.view('local-agent')['revision'])
    provider._lock.acquire()
    try:
        draft=asyncio.create_task(tools.execute('local-agent','gmail:draft','draft',to='recipient@example.test',subject='Subject',body='Body'))
        await asyncio.sleep(.05)
        permissions.save('local-agent',selections(draft='ask'),permissions.view('local-agent')['revision'])
    finally:
        provider._lock.release()
    assert not (await draft)['ok']
    assert not any(call[1]=='create' for call in service.calls)


@pytest.mark.asyncio
async def test_operator_permission_api_auth_conflicts_revoked_agents_and_audit(tmp_path):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        broker.agent_registry=AgentRegistry(tmp_path/'agents.sqlite3')
        broker.agent_registry.register('local-agent')
        view=(await client.get('/api/permissions?agent_id=local-agent')).json()['data']
        payload={'agent_id':'local-agent','permissions':selections(),'revision':view['revision']}
        assert (await client.post('/api/permissions',json=payload,headers={'Authorization':'Bearer '+agent_token})).status_code==401
        saved=await client.post('/api/permissions',json=payload)
        assert saved.json()['data']['permissions']==selections()
        assert (await client.post('/api/permissions',json=payload)).status_code==409
        broker.agent_registry.revoke('local-agent')
        payload['revision']=saved.json()['data']['revision']
        assert (await client.post('/api/permissions',json=payload)).status_code==400
        activity=(await client.get('/api/activity')).json()['data']['activity']
        assert any(r['agent']=='operator' and r['credential_requested']=='permissions:update' and r['decision']=='completed' for r in activity)


def test_time_windows_require_explicit_acknowledgment_not_silent_broadening(tmp_path):
    from broker.policy_engine import PolicyEngine
    import datetime
    broker, _, _, _, permissions=setup(tmp_path)
    rules={'policies':[{'name':'work-hours','agent':'local-agent','credential':'gmail:read','auto_approve':True,'time_window':{'start':'09:00','end':'17:00'}}]}
    with open(broker.config.policies_path,'w') as stream: yaml.safe_dump(rules,stream)
    before=open(broker.config.policies_path,'rb').read()
    view=permissions.view('local-agent')
    assert view['time_windows']==[{'resource':'gmail:read','policy':'work-hours','start':'09:00','end':'17:00'}]
    with pytest.raises(ValueError,match='acknowledge'):
        permissions.save('local-agent',selections(),view['revision'])
    assert open(broker.config.policies_path,'rb').read()==before
    permissions.save('local-agent',selections(),view['revision'],acknowledge_time_windows=True)
    assert PolicyEngine.from_file(broker.config.policies_path).evaluate('local-agent','gmail:read',datetime.time(23)).auto_approve


@pytest.mark.asyncio
async def test_malformed_policy_is_actionable_and_save_does_not_mutate(tmp_path):
    async with dashboard(tmp_path) as (client,broker,service,tools,mcp,agent_token):
        broker.agent_registry=AgentRegistry(tmp_path/'agents.sqlite3')
        broker.agent_registry.register('local-agent')
        with open(broker.config.policies_path,'w') as stream: stream.write('policies: [')
        response=await client.get('/api/permissions?agent_id=local-agent')
        assert response.status_code==400
        assert 'Repair' in response.json()['reason']
        assert open(broker.config.policies_path).read()=='policies: ['


@pytest.mark.asyncio
async def test_resolved_policy_proposal_cannot_override_a_newer_permission_save(tmp_path):
    broker, _, _, _, permissions=setup(tmp_path)
    request=asyncio.create_task(broker.add_policy({'name':'override-deny','agent':'local-agent','credential':'gmail:read','auto_approve':True},agent='local-agent'))
    approval=await pending(broker)
    broker.approvals.resolve(approval,True)
    # The approval future is done, but its task has not resumed yet.
    permissions.save('local-agent',selections(read='deny'),permissions.view('local-agent')['revision'])
    assert not (await request)['added']
    decision=broker.engine.evaluate('local-agent','gmail:read')
    assert not decision.auto_approve and not decision.escalate


@pytest.mark.asyncio
async def test_real_http_permissions_change_an_existing_authenticated_agents_access(tmp_path):
    import requests
    from fastmcp import Client
    from tests.test_identity_http import server
    async with server(tmp_path) as (base,reader,writer,operator,registry):
        headers={'Authorization':'Bearer '+operator}
        async with Client(base+'/mcp',auth=reader,timeout=10) as client:
            assert (await client.call_tool('gmail.search',{'query':'is:unread'})).data['ok']
            view=(await asyncio.to_thread(requests.get,base+'/api/permissions?agent_id=reader',headers=headers,timeout=3)).json()['data']
            saved=await asyncio.to_thread(requests.post,base+'/api/permissions',headers=headers,json={'agent_id':'reader','permissions':selections(read='deny',draft='allow',send='ask'),'revision':view['revision']},timeout=3)
            assert saved.json()['ok']
            assert not (await client.call_tool('gmail.search',{'query':'is:unread'})).data['ok']
            assert (await client.call_tool('gmail.draft',{'to':'recipient@example.test','subject':'Subject','body':'Body'})).data['ok']
            sending=asyncio.create_task(client.call_tool('gmail.send_draft',{'draft_id':'draft-1'}))
            async with asyncio.timeout(5):
                while True:
                    status=(await asyncio.to_thread(requests.get,base+'/api/status',headers=headers,timeout=3)).json()['data']
                    if status['pending']: break
                    await asyncio.sleep(.02)
            assert status['pending']['agent']=='reader'
            assert not sending.done()
            changed=await asyncio.to_thread(requests.post,base+'/api/permissions',headers=headers,json={'agent_id':'reader','permissions':selections(read='deny',draft='allow',send='deny'),'revision':saved.json()['data']['revision']},timeout=3)
            assert changed.json()['ok']
            assert not (await sending).data['ok']
            stale=await asyncio.to_thread(requests.post,base+'/api/approval',headers=headers,json={'id':status['pending']['id'],'approved':True},timeout=3)
            assert stale.status_code==409
        async with Client(base+'/mcp',auth=writer,timeout=10) as client:
            assert (await client.call_tool('gmail.draft',{'to':'recipient@example.test','subject':'Subject','body':'Body'})).data['ok']
            assert not (await client.call_tool('gmail.search',{'query':'is:unread'})).data['ok']
        rows=[json.loads(line) for line in (tmp_path/'audit.log').read_text().splitlines()]
        assert not any(r['credential_requested']=='gmail:send' and r['decision']=='completed' for r in rows)
