import asyncio
import json
import threading
from contextlib import asynccontextmanager

import httpx2 as httpx
import pytest

from broker.dashboard import create_dashboard
from broker.agent_registry import AgentRegistry
from broker.grants import TemporaryGrants
from broker.integrations.github import ACCOUNT_NAME as GITHUB_ACCOUNT, TOKEN_NAME as GITHUB_TOKEN
from broker.integrations.github import GitHubError
from broker.connections import ACCOUNT_NAME as GMAIL_ACCOUNT
from broker.integrations.gmail import TOKEN_NAME as GMAIL_TOKEN
from broker.mcp_server import build_mcp
from tests.test_gmail import make_tools


class FakeGitHub:
    def __init__(self, store):
        import threading
        self.store = store
        self._lock = threading.RLock()
        self._suspended = False

    def info(self):
        if self._suspended or GITHUB_TOKEN not in self.store.list_names():
            return {'service': 'github', 'status': 'disconnected', 'account': None}
        return {'service': 'github', 'status': 'connected',
                'account': json.loads(self.store.retrieve(GITHUB_ACCOUNT))}

    def connect(self, token):
        if token == 'rejected-candidate':
            raise GitHubError('GitHub authorization needs renewal. Reconnect GitHub.')
        self.store.store(GITHUB_TOKEN, token)
        self.store.store(GITHUB_ACCOUNT, json.dumps({'login': 'safe-user', 'id': 42}))
        self._suspended = False
        return {'login': 'safe-user', 'id': 42, 'token': token}

    def disconnect(self):
        with self._lock:
            self._suspended = True
            for name in (GITHUB_TOKEN, GITHUB_ACCOUNT):
                if name in self.store.list_names():
                    self.store.delete(name)


@asynccontextmanager
async def dashboard(tmp_path):
    broker, _, _, tools = make_tools(tmp_path)
    github = FakeGitHub(broker.store)
    mcp = build_mcp(broker, gmail_tools=tools)
    app = create_dashboard(mcp.http_app(path='/mcp'), broker, tools,
                           'operator-private', github=github)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url='http://127.0.0.1:8765',
            headers={'Authorization': 'Bearer operator-private'},
        ) as client:
            yield client, broker, github, tools


@pytest.mark.asyncio
async def test_connections_endpoints_require_operator_auth_and_return_safe_metadata(tmp_path):
    async with dashboard(tmp_path) as (client, broker, github, tools):
        assert (await client.get('/api/connections', headers={'Authorization': ''})).status_code == 401
        assert (await client.get('/api/reconnect-status', headers={'Authorization': ''})).status_code == 401
        result = (await client.get('/api/connections')).json()
        assert result['ok']
        assert result['data']['services'] == [
            {'service': 'gmail', 'status': 'disconnected', 'account': None,
             'reconnecting': False, 'agents': []},
            {'service': 'github', 'status': 'disconnected', 'account': None, 'agents': []},
        ]
        assert (await client.post('/api/connection-disconnect', json={'service':'github'},
                                  headers={'Authorization':''})).status_code == 401
        assert (await client.get('/app/connections.js')).status_code == 200


@pytest.mark.asyncio
async def test_connections_show_active_agents_baseline_permissions_and_temporary_grants(tmp_path):
    async with dashboard(tmp_path) as (client, broker, github, tools):
        registry = AgentRegistry(tmp_path / 'connection-agents.sqlite3')
        active = registry.register('researcher')['agent']
        inactive = registry.register('former-helper')['agent']
        registry.revoke(inactive['id'])
        broker.agent_registry = registry
        broker.temporary_grants = TemporaryGrants(registry)
        grant = broker.temporary_grants.create(active['id'], 'gmail:read', 'allow', 20)

        result = (await client.get('/api/connections')).json()['data']['services']
        gmail, github_info = result
        assert len(gmail['agents']) == 1
        assert gmail['agents'][0]['id'] == active['id']
        assert gmail['agents'][0]['name'] == 'researcher'
        assert set(gmail['agents'][0]['permissions']) == {'gmail:read','gmail:draft','gmail:send'}
        assert gmail['agents'][0]['temporary_grants'] == [{
            'resource':'gmail:read','permission':'allow','expires_at':grant['expires_at'],
        }]
        assert github_info['agents'][0]['temporary_grants'] == []
        assert 'reason' not in json.dumps(result)


@pytest.mark.asyncio
async def test_disconnect_is_local_and_invalidates_requests(tmp_path):
    async with dashboard(tmp_path) as (client, broker, github, tools):
        broker.store.store(GMAIL_TOKEN, '{"refresh_token":"gmail-private"}')
        broker.store.store(GMAIL_ACCOUNT, '{"email":"mail@example.test"}')
        broker.store.store(GITHUB_TOKEN, 'github-private-token')
        broker.store.store(GITHUB_ACCOUNT, '{"login":"safe-user","id":42}')
        start = broker.policy_revision

        gmail = await client.post('/api/connection-disconnect', json={'service':'gmail'})
        assert gmail.json()['data'] == {'service':'gmail','status':'disconnected'}
        assert GMAIL_TOKEN not in broker.store.list_names()
        assert GMAIL_ACCOUNT not in broker.store.list_names()

        github_response = await client.post('/api/connection-disconnect', json={'service':'github'})
        assert github_response.json()['data'] == {'service':'github','status':'disconnected'}
        assert GITHUB_TOKEN not in broker.store.list_names()
        assert GITHUB_ACCOUNT not in broker.store.list_names()
        assert broker.policy_revision == start + 4
        assert 'gmail-private' not in json.dumps((await client.get('/api/activity')).json())


@pytest.mark.asyncio
async def test_github_connect_token_is_transient_and_never_in_response_or_audit(tmp_path):
    async with dashboard(tmp_path) as (client, broker, github, tools):
        token = 'github-super-private-token'
        response = await client.post('/api/github-connect', json={'token': token})
        assert response.status_code == 200
        assert response.json()['data'] == {
            'service':'github', 'status':'connected', 'account':{'login':'safe-user','id':42},
        }
        assert token not in response.text
        assert token not in json.dumps((await client.get('/api/activity')).json())
        info = (await client.get('/api/connections')).json()['data']['services'][1]
        assert info == {'service':'github','status':'connected','account':{'login':'safe-user','id':42},'agents':[]}


@pytest.mark.asyncio
async def test_reconnect_status_is_safe_and_github_token_payload_is_validated(tmp_path):
    async with dashboard(tmp_path) as (client, broker, github, tools):
        assert (await client.get('/api/reconnect-status')).json()['data'] == {'active':False,'state':'idle'}
        bad = await client.post('/api/github-connect', json={'token': ['not-a-token']})
        assert bad.status_code == 400
        assert (await client.post('/api/connection-disconnect', json={'service':'other'})).status_code == 400


@pytest.mark.asyncio
async def test_failed_github_candidate_keeps_existing_connection_usable(tmp_path):
    async with dashboard(tmp_path) as (client, broker, github, tools):
        broker.store.store(GITHUB_TOKEN, 'working-private-token')
        broker.store.store(GITHUB_ACCOUNT, '{"login":"old-user","id":7}')
        result = await client.post('/api/github-connect', json={'token':'rejected-candidate'})
        assert result.status_code == 400
        assert broker.store.retrieve(GITHUB_TOKEN) == 'working-private-token'
        assert github._suspended is False
        assert (await client.get('/api/connections')).json()['data']['services'][1]['account'] == {
            'login':'old-user','id':7,
        }


@pytest.mark.asyncio
async def test_github_connect_and_disconnect_are_serialized(tmp_path):
    async with dashboard(tmp_path) as (client, broker, github, tools):
        entered = threading.Event()
        release = threading.Event()
        original_connect = github.connect

        def slow_connect(token):
            entered.set()
            assert release.wait(2)
            return original_connect(token)

        github.connect = slow_connect
        connect = asyncio.create_task(client.post('/api/github-connect', json={'token':'candidate'}))
        assert await asyncio.to_thread(entered.wait, 1)
        disconnect = asyncio.create_task(client.post('/api/connection-disconnect', json={'service':'github'}))
        await asyncio.sleep(0.02)
        assert not disconnect.done()
        release.set()
        assert (await connect).status_code == 200
        assert (await disconnect).status_code == 200
        assert GITHUB_TOKEN not in broker.store.list_names()


@pytest.mark.asyncio
async def test_canceled_github_connect_keeps_mutation_lock_until_worker_finishes(tmp_path):
    async with dashboard(tmp_path) as (client, broker, github, tools):
        entered = threading.Event()
        release = threading.Event()
        original_connect = github.connect

        def slow_connect(token):
            entered.set()
            assert release.wait(2)
            return original_connect(token)

        github.connect = slow_connect
        connect = asyncio.create_task(client.post('/api/github-connect', json={'token':'candidate'}))
        assert await asyncio.to_thread(entered.wait, 1)
        connect.cancel()
        disconnect = asyncio.create_task(client.post('/api/connection-disconnect', json={'service':'github'}))
        await asyncio.sleep(0.02)
        assert not disconnect.done()
        connect.cancel()
        await asyncio.sleep(0.02)
        assert not disconnect.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await connect
        assert (await disconnect).status_code == 200
        assert GITHUB_TOKEN not in broker.store.list_names()

@pytest.mark.asyncio
async def test_credential_unlock_failure_has_safe_actionable_error(tmp_path, monkeypatch):
    from broker.credential_store import CredentialDecryptionError
    async with dashboard(tmp_path) as (client,broker,github,tools):
        broker.store.store(GMAIL_TOKEN,'sample-only')
        def failed(*args,**kwargs):
            raise CredentialDecryptionError('private-credential-name-and-secret')
        monkeypatch.setattr(tools.gmail,'call',failed)
        response = await client.get('/api/connections')
        assert response.status_code == 503
        data = response.json()
        assert data['code'] == 'credentials_locked'
        assert 'master password' in data['reason']
        assert 'private-credential-name-and-secret' not in response.text
