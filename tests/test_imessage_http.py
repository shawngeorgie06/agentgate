import json

import pytest

from tests.test_dashboard import dashboard


STATUS = {
    'available': True, 'enabled': False, 'paired': False, 'running': False,
    'agent': None,
    'model': {'available': True, 'reason': ''},
    'pairing': {'code': 'ABC-123', 'expires_at': '2026-10-12T12:05:00+00:00'},
    'recent': [{'status': 'completed', 'claimed_at': '2026-10-12T12:00:00+00:00',
                'attempted_at': '2026-10-12T12:00:01+00:00', 'finished_at': '2026-10-12T12:00:02+00:00'}],
    'error': None,
}


class FakeIMessage:
    """Stands in for broker.imessage_service with the agreed interface."""

    def __init__(self, status=STATUS):
        self.status_value = dict(status)
        self.calls = []
        self.raise_on = {}

    def _record(self, name, *args):
        self.calls.append((name, *args))
        if name in self.raise_on:
            raise self.raise_on[name]
        return dict(self.status_value)

    def status(self):
        return self._record('status')

    async def snapshot(self):
        return self._record('snapshot')

    async def start_pairing(self, agent_id):
        return self._record('start_pairing', agent_id)

    async def cancel_pairing(self):
        return self._record('cancel_pairing')

    async def enable(self):
        return self._record('enable')

    async def disable(self):
        return self._record('disable')

    async def unpair(self):
        return self._record('unpair')


MUTATIONS = ['imessage-pair-cancel', 'imessage-enable', 'imessage-disable', 'imessage-unpair']


@pytest.mark.asyncio
async def test_imessage_routes_require_operator_auth_before_touching_service(tmp_path):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        fake = FakeIMessage()
        broker.imessage_service = fake
        for headers in ({'Authorization': ''}, {'Authorization': f'Bearer {agent_token}'}):
            assert (await client.get('/api/imessage', headers=headers)).status_code == 401
            assert (await client.post('/api/imessage-pair', json={'agent_id': 'helper'}, headers=headers)).status_code == 401
            for action in MUTATIONS:
                assert (await client.post(f'/api/{action}', json={}, headers=headers)).status_code == 401
        assert fake.calls == []


@pytest.mark.asyncio
async def test_status_passes_service_status_through_unchanged(tmp_path):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        fake = FakeIMessage()
        broker.imessage_service = fake
        response = await client.get('/api/imessage')
        assert response.status_code == 200
        assert response.headers['cache-control'] == 'no-store'
        assert response.json() == {'ok': True, 'data': STATUS}
        assert fake.calls == [('snapshot',)]


@pytest.mark.asyncio
async def test_missing_or_none_service_reports_unavailable_defaults(tmp_path):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        expected = {
            'available': False, 'enabled': False, 'paired': False, 'running': False,
            'agent': None,
            'model': {'available': False, 'reason': 'iMessage is not available on this broker.'},
            'pairing': None, 'recent': [], 'error': None,
        }
        assert 'imessage_service' not in vars(broker)
        missing = await client.get('/api/imessage')
        assert missing.status_code == 200
        assert missing.json() == {'ok': True, 'data': expected}
        broker.imessage_service = None
        none = await client.get('/api/imessage')
        assert none.json() == {'ok': True, 'data': expected}


@pytest.mark.asyncio
async def test_mutations_report_unavailable_without_side_effects(tmp_path):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        broker.imessage_service = None
        pair = await client.post('/api/imessage-pair', json={'agent_id': 'helper'})
        assert pair.status_code == 503
        assert pair.json()['ok'] is False
        for action in MUTATIONS:
            response = await client.post(f'/api/{action}', json={})
            assert response.status_code == 503
            assert response.json()['ok'] is False


@pytest.mark.asyncio
async def test_pair_starts_pairing_for_valid_agent_and_returns_status(tmp_path):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        fake = FakeIMessage()
        broker.imessage_service = fake
        response = await client.post('/api/imessage-pair', json={'agent_id': 'helper-1'})
        assert response.status_code == 200
        assert response.json() == {'ok': True, 'data': STATUS}
        assert fake.calls == [('start_pairing', 'helper-1')]


@pytest.mark.asyncio
@pytest.mark.parametrize('payload', [
    {},
    {'agent_id': None},
    {'agent_id': 42},
    {'agent_id': ['helper']},
    {'agent_id': ''},
    {'agent_id': 'a' * 65},
    {'agent_id': '../outside'},
    {'agent_id': 'bad name!'},
])
async def test_pair_rejects_invalid_agent_id_before_service_call(tmp_path, payload):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        fake = FakeIMessage()
        broker.imessage_service = fake
        response = await client.post('/api/imessage-pair', json=payload)
        assert response.status_code == 400
        assert response.json()['ok'] is False
        assert fake.calls == []


@pytest.mark.asyncio
async def test_pair_maps_value_error_to_safe_400(tmp_path):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        fake = FakeIMessage()
        fake.raise_on['start_pairing'] = ValueError('internal detail /Users/someone/chat.db')
        broker.imessage_service = fake
        response = await client.post('/api/imessage-pair', json={'agent_id': 'retired-helper'})
        assert response.status_code == 400
        body = response.json()
        assert body['ok'] is False
        assert body['reason'] == 'Choose an active enrolled agent to pair with iMessage.'
        assert 'chat.db' not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize('action,method', [
    ('imessage-pair-cancel', 'cancel_pairing'),
    ('imessage-enable', 'enable'),
    ('imessage-disable', 'disable'),
    ('imessage-unpair', 'unpair'),
])
async def test_mutation_actions_call_matching_service_method(tmp_path, action, method):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        fake = FakeIMessage()
        broker.imessage_service = fake
        response = await client.post(f'/api/{action}', json={})
        assert response.status_code == 200
        assert response.json() == {'ok': True, 'data': STATUS}
        assert fake.calls == [(method,)]


@pytest.mark.asyncio
async def test_mutations_require_json_object_body(tmp_path):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        fake = FakeIMessage()
        broker.imessage_service = fake
        for action in ['imessage-pair'] + MUTATIONS:
            assert (await client.post(f'/api/{action}', content='not json')).status_code == 400
            assert (await client.post(f'/api/{action}', content='[]')).status_code == 400
        assert (await client.post('/api/imessage-pair', content='x' * 262145)).status_code == 413
        assert fake.calls == []


@pytest.mark.asyncio
async def test_unexpected_service_failure_is_generic_500(tmp_path):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        fake = FakeIMessage()
        fake.raise_on['enable'] = RuntimeError('private path /Users/someone/chat.db')
        broker.imessage_service = fake
        response = await client.post('/api/imessage-enable', json={})
        assert response.status_code == 500
        assert response.json()['ok'] is False
        assert 'chat.db' not in response.text


@pytest.mark.asyncio
async def test_imessage_actions_are_post_only_and_frontend_is_served(tmp_path):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        fake = FakeIMessage()
        broker.imessage_service = fake
        assert (await client.get('/api/imessage-pair')).status_code == 404
        assert (await client.post('/api/imessage', json={})).status_code == 404
        assert fake.calls == []
        frontend = await client.get('/app/imessage.js')
        assert frontend.status_code == 200
        assert 'export async function renderIMessage' in frontend.text
        assert "default-src 'self'" in frontend.headers['content-security-policy']
        page = await client.get('/app')
        assert 'data-view="imessage"' in page.text
        assert 'id="imessage-view"' in page.text
