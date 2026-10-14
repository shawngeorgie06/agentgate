import pytest

from broker.agent_registry import AgentRegistry
from broker.grants import TemporaryGrants
from tests.test_dashboard import dashboard


@pytest.mark.asyncio
async def test_operator_grant_api_auth_create_revoke_and_history(tmp_path):
    async with dashboard(tmp_path) as (client, broker, service, tools, mcp, agent_token):
        frontend = await client.get('/app/grants.js')
        assert frontend.status_code == 200
        assert 'export async function renderGrants' in frontend.text
        registry = AgentRegistry(tmp_path / 'grants-agents.sqlite3')
        registry.register('helper')
        broker.agent_registry = registry
        broker.temporary_grants = TemporaryGrants(registry)

        unauthenticated = await client.get('/api/grants', headers={'Authorization': ''})
        assert unauthenticated.status_code == 401
        initial = await client.get('/api/grants')
        assert initial.json()['data']['available'] is True
        assert initial.json()['data']['agents'][0]['id'] == 'helper'
        assert initial.json()['data']['grants'] == []

        payload = {'agent_id': 'helper', 'resource': 'github:read', 'permission': 'allow',
                   'minutes': 15, 'reason': 'review a repository'}
        before_revision = broker.policy_revision
        created = await client.post('/api/grant-create', json=payload,
                                    headers={'Authorization': f'Bearer {agent_token}'})
        assert created.status_code == 401
        created = await client.post('/api/grant-create', json=payload)
        assert created.status_code == 200
        grant = created.json()['data']['grant']
        assert grant['resource'] == 'github:read' and grant['status'] == 'active'
        assert broker.policy_revision == before_revision + 1
        assert broker.temporary_grants.active_grant('helper', 'github:read')['id'] == grant['id']

        duplicate = await client.post('/api/grant-create', json=payload)
        assert duplicate.status_code == 400
        forbidden_write_allow = await client.post('/api/grant-create', json={
            **payload, 'resource': 'github:write', 'permission': 'allow',
        })
        assert forbidden_write_allow.status_code == 400

        revision_before_revoke = broker.policy_revision
        revoked = await client.post('/api/grant-revoke', json={'grant_id': grant['id']})
        assert revoked.status_code == 200
        assert revoked.json()['data']['revoked'] is True
        assert broker.policy_revision == revision_before_revoke + 1
        assert revoked.json()['data']['grants'][0]['status'] == 'revoked'
        missing = await client.post('/api/grant-revoke', json={'grant_id': 'unknown'})
        assert missing.status_code == 400

        activity = (await client.get('/api/activity')).json()['data']['activity']
        assert any(row['credential_requested'] == 'temporary-access' and row['decision'] == 'completed'
                   for row in activity)
