"""End-to-end enrollment, temporary override and separate service policies."""
import asyncio
import requests
import pytest
from fastmcp import Client
from tests.test_identity_http import server

@pytest.mark.asyncio
async def test_live_http_grant_lifts_deny_and_revocation_restores_it(tmp_path):
    async with server(tmp_path) as (base, reader, writer, operator, registry):
        headers = {'Authorization': 'Bearer ' + operator}
        async with Client(base + '/mcp', auth=writer, timeout=10) as client:
            assert not (await client.call_tool('gmail.search', {'query': 'is:unread'})).data['ok']
            assert (await asyncio.to_thread(requests.get, base+'/api/grants', headers={'Authorization':'Bearer '+writer}, timeout=2)).status_code == 401
            response = await asyncio.to_thread(requests.post, base+'/api/grant-create', headers=headers,
                json={'agent_id':'writer','resource':'gmail:read','permission':'allow','minutes':1,'reason':'Sample workflow'}, timeout=2)
            assert response.json()['ok'], response.text
            grant = response.json()['data']['grant']
            assert (await client.call_tool('gmail.search', {'query':'is:unread'})).data['ok']
            response = await asyncio.to_thread(requests.post, base+'/api/grant-revoke',headers=headers,json={'grant_id':grant['id']},timeout=2)
            assert response.json()['ok'], response.text
            assert not (await client.call_tool('gmail.search', {'query':'is:unread'})).data['ok']
            assert not (await client.call_tool('github.repos', {'agent':'reader'})).data['ok']
        text = (tmp_path/'audit.log').read_text()
        assert writer not in text and operator not in text
