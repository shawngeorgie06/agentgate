"""Real HTTP integration: authentication context, policies, and session revocation."""
import asyncio
import json
import os
import socket
import subprocess
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
import requests
from fastmcp import Client

from broker.agent_registry import AgentRegistry
from broker.http_auth import create_token_file, read_token_file

_SERVER = '''
from tests.test_gmail import FakeService
from broker.integrations import gmail
fake = FakeService()
original = gmail.Gmail.__init__
def init(self, store, service_factory=None):
    original(self, store, service_factory=lambda: fake)
gmail.Gmail.__init__ = init
from broker.main import main
main()
'''


@asynccontextmanager
async def server(tmp_path):
    for name in ('agent-token', 'operator-token'):
        create_token_file(str(tmp_path/name))
    reader = read_token_file(str(tmp_path/'agent-token'))
    operator = read_token_file(str(tmp_path/'operator-token'))
    registry = AgentRegistry(tmp_path/'agents.sqlite3')
    registry.import_token('reader', reader)
    writer = registry.register('writer')['token']
    policies = tmp_path/'policies.yaml'
    policies.write_text('''policies:
  - name: reader
    agent: reader
    credential: gmail:read
    auto_approve: true
  - name: writer-drafts
    agent: writer
    credential: gmail:draft
    auto_approve: true
  - name: writer-sends
    agent: writer
    credential: gmail:send
    auto_approve: false
    escalate: true
  - name: deny
    agent: "*"
    credential: "*"
    auto_approve: false
    escalate: false
''')
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1',0)); port=reservation.getsockname()[1]
    log = (tmp_path/'server.log').open('w')
    process = subprocess.Popen([sys.executable,'-c',_SERVER,'--app','--no-open','--port',str(port),
                                '--token-file',str(tmp_path/'agent-token'),'--bootstrap-agent','reader',
                                '--operator-token-file',str(tmp_path/'operator-token')],
        cwd=Path(__file__).resolve().parents[1], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log,
        env={**os.environ,'POLICIES_PATH':str(policies),'CREDENTIALS_PATH':str(tmp_path/'credentials.json'),
             'STATE_PATH':str(tmp_path/'mode.json'),'LOGS_PATH':str(tmp_path/'audit.log'),
             'AGENTS_PATH':str(tmp_path/'agents.sqlite3'),'AGENTGATE_MASTER_PASSWORD':'dummy-only',
             'ESCALATION_TIMEOUT_SECONDS':'5'})
    base=f'http://127.0.0.1:{port}'
    try:
        async with asyncio.timeout(10):
            while True:
                assert process.poll() is None, 'Sample broker failed to start.'
                try:
                    response=await asyncio.to_thread(requests.get,base+'/api/status',timeout=1)
                    if response.status_code==401: break
                except requests.ConnectionError: pass
                await asyncio.sleep(.05)
        yield base, reader, writer, operator, registry
    finally:
        process.terminate()
        await asyncio.to_thread(process.wait,timeout=5)
        log.close()


@pytest.mark.asyncio
async def test_real_authenticated_agents_cannot_impersonate_or_use_each_others_policies(tmp_path):
    async with server(tmp_path) as (base,reader,writer,operator,registry):
        async with Client(base+'/mcp',auth=reader,timeout=10) as client:
            assert (await client.call_tool('gmail.search',{'query':'is:unread'})).data['ok']
            denied=(await client.call_tool('gmail.draft',{'to':'recipient@example.test','subject':'Subject','body':'Body'})).data
            assert denied['ok'] is False
            forged=(await client.call_tool('gmail.draft',{'agent':'writer','to':'recipient@example.test','subject':'Subject','body':'Body'})).data
            assert forged['ok'] is False
        async with Client(base+'/mcp',auth=writer,timeout=10) as client:
            assert (await client.call_tool('gmail.draft',{'to':'recipient@example.test','subject':'Subject','body':'Body'})).data['ok']
            assert not (await client.call_tool('gmail.search',{'query':'is:unread'})).data['ok']
        audit=(tmp_path/'audit.log').read_text()
        assert reader not in audit and writer not in audit and operator not in audit
        rows=[json.loads(line) for line in audit.splitlines()]
        assert {r['agent'] for r in rows} == {'reader','writer'}
        assert not any(r['credential_requested']=='gmail:send' for r in rows)


@pytest.mark.asyncio
async def test_real_session_and_pending_send_fail_after_operator_revocation(tmp_path):
    async with server(tmp_path) as (base,reader,writer,operator,registry):
        headers={'Authorization':'Bearer '+operator}
        async with Client(base+'/mcp',auth=writer,timeout=10) as client:
            assert (await client.call_tool('broker.status')).data['mode']
            send=asyncio.create_task(client.call_tool('gmail.send_draft',{'draft_id':'draft-1'}))
            async with asyncio.timeout(5):
                while True:
                    status=(await asyncio.to_thread(requests.get,base+'/api/status',headers=headers,timeout=2)).json()['data']
                    if status['pending']: break
                    await asyncio.sleep(.02)
            assert status['pending']['agent']=='writer'
            revoked=await asyncio.to_thread(requests.post,base+'/api/agent-revoke',headers=headers,json={'id':'writer'},timeout=2)
            assert revoked.json()['ok']
            approved=await asyncio.to_thread(requests.post,base+'/api/approval',headers=headers,json={'id':status['pending']['id'],'approved':True},timeout=2)
            assert approved.json()['ok']
            assert not (await send).data['ok']
            # Revocation must invalidate the same established client, not just new logins.
            with pytest.raises(Exception):
                await client.call_tool('broker.status')
        assert registry.authenticate(writer) is None
        rows=[json.loads(line) for line in (tmp_path/'audit.log').read_text().splitlines()]
        sends=[r['decision'] for r in rows if r['credential_requested']=='gmail:send']
        assert 'denied' in sends and 'completed' not in sends
