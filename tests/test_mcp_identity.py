import asyncio
import json

import pytest
from fastmcp import Client
from fastmcp.server.auth import AccessToken

from broker.agent_registry import AgentRegistry
from broker.main import build_broker
from broker.mcp_server import build_mcp
from broker.http_auth import RegistryTokenVerifier
from tests.test_main import _cfg


@pytest.mark.asyncio
async def test_mcp_identity_comes_from_live_token_and_rejects_forgery(tmp_path, monkeypatch):
    registry = AgentRegistry(tmp_path / "agents.sqlite3")
    issued = registry.register("worker-a")
    token = issued["token"]
    broker = build_broker(_cfg(tmp_path), "pw")
    broker.agent_registry = registry
    monkeypatch.setattr("broker.mcp_server.get_access_token",
                        lambda: AccessToken(token=token, client_id="worker-a", scopes=["agentgate"]))
    mcp = build_mcp(broker, trusted_agent="stdio-owner")
    async with Client(mcp) as client:
        assert (await client.call_tool("broker.status")).data["requests"] == 0
        assert (await client.call_tool("broker.status", {"agent": "forged"})).data == {}
        assert (await client.call_tool("broker.status", {"agent": "worker-a"})).data["mode"]

        registry.revoke("worker-a")
        assert (await client.call_tool("broker.status", {"agent": "worker-a"})).data == {}
    verifier = RegistryTokenVerifier(registry)
    assert await verifier.verify_token(token) is None


@pytest.mark.asyncio
async def test_trusted_inprocess_identity_ignores_caller_claim(tmp_path):
    broker = build_broker(_cfg(tmp_path), "pw")
    mcp = build_mcp(broker, trusted_agent="operator-launched-agent")
    async with Client(mcp) as client:
        assert (await client.call_tool("broker.status")).data["mode"]
        assert (await client.call_tool("broker.status", {"agent": "attacker"})).data == {}


@pytest.mark.asyncio
async def test_revocation_while_credential_approval_is_pending_blocks_grant(tmp_path):
    broker = build_broker(_cfg(tmp_path), "pw")
    registry = AgentRegistry(tmp_path / "agents.sqlite3")
    issued = registry.register("worker-a")
    active = True
    task = asyncio.create_task(
        broker.request_credential("worker-a", "demo-key", identity_guard=lambda: active)
    )
    async with asyncio.timeout(3):
        while broker.approvals.get_pending() is None:
            await asyncio.sleep(0.01)
    active = False
    registry.revoke("worker-a")
    broker.approvals.resolve(broker.approvals.get_pending(), True)
    result = await task
    assert result["granted"] is False
    assert result["value"] is None
    assert "no longer active" in result["reason"]


@pytest.mark.asyncio
async def test_policy_approval_reviews_and_applies_the_same_frozen_proposal(tmp_path):
    broker = build_broker(_cfg(tmp_path), "pw")
    proposal = {
        "name": "read-only-worker", "agent": "worker-a", "credential": "gmail:read",
        "auto_approve": True, "escalate": False, "review_note": "private-proposal-marker",
    }
    task = asyncio.create_task(broker.add_policy(proposal, agent="worker-a"))
    async with asyncio.timeout(3):
        while broker.approvals.get_pending() is None:
            await asyncio.sleep(0.01)
    request = broker.approvals.get_pending()
    assert json.loads(request.details) == proposal
    proposal["agent"] = "*"
    broker.approvals.resolve(request, True)
    result = await task
    assert result["added"] is True
    assert broker.list_policies()[0]["agent"] == "worker-a"
    lines = open(broker.config.logs_path).read().splitlines()
    events = [json.loads(line) for line in lines]
    assert [event["decision"] for event in events] == ["escalated", "approved", "completed"]
    assert all(event["agent"] == "worker-a" for event in events)
    assert all(event["credential_requested"] == "policy.add:read-only-worker" for event in events)
    assert "private-proposal-marker" not in "\n".join(lines)


@pytest.mark.asyncio
async def test_policy_denial_and_inactive_identity_are_audited_without_proposal_body(tmp_path):
    broker = build_broker(_cfg(tmp_path), "pw")
    proposal = {
        "name": "sensitive-policy-name", "agent": "worker-a", "credential": "private-marker",
        "auto_approve": True, "escalate": False,
    }
    task = asyncio.create_task(broker.add_policy(proposal, agent="worker-a"))
    async with asyncio.timeout(3):
        while broker.approvals.get_pending() is None:
            await asyncio.sleep(0.01)
    request = broker.approvals.get_pending()
    broker.approvals.resolve(request, False)
    result = await task
    assert result["added"] is False

    inactive = await broker.add_policy(
        {**proposal, "name": "inactive-policy"},
        agent="worker-a", identity_guard=lambda: False,
    )
    assert inactive["added"] is False
    lines = open(broker.config.logs_path).read().splitlines()
    events = [json.loads(line) for line in lines]
    assert [event["decision"] for event in events] == ["escalated", "denied", "denied"]
    assert [event["credential_requested"] for event in events] == [
        "policy.add:sensitive-policy-name", "policy.add:sensitive-policy-name", "policy.add:inactive-policy",
    ]
    assert "private-marker" not in "\n".join(lines)


@pytest.mark.asyncio
async def test_revocation_after_policy_approval_is_audited_and_blocks_apply(tmp_path):
    broker = build_broker(_cfg(tmp_path), "pw")
    active = True
    proposal = {
        "name": "revoked-proposal", "agent": "worker-a", "credential": "private-marker",
        "auto_approve": True, "escalate": False,
    }
    before = broker.list_policies()
    task = asyncio.create_task(
        broker.add_policy(proposal, agent="worker-a", identity_guard=lambda: active)
    )
    async with asyncio.timeout(3):
        while broker.approvals.get_pending() is None:
            await asyncio.sleep(0.01)
    request = broker.approvals.get_pending()
    active = False
    broker.approvals.resolve(request, True)
    result = await task
    assert result["added"] is False
    assert broker.list_policies() == before
    lines = open(broker.config.logs_path).read().splitlines()
    events = [json.loads(line) for line in lines]
    assert [event["decision"] for event in events] == ["escalated", "approved", "denied"]
    assert "private-marker" not in "\n".join(lines)


@pytest.mark.asyncio
async def test_invalid_policy_logs_failure_with_frozen_name_only(tmp_path):
    broker = build_broker(_cfg(tmp_path), "pw")
    proposal = {"name": "invalid-frozen-name", "agent": "worker-a", "private": "no-policy-body"}
    task = asyncio.create_task(broker.add_policy(proposal, agent="worker-a"))
    async with asyncio.timeout(3):
        while broker.approvals.get_pending() is None:
            await asyncio.sleep(0.01)
    request = broker.approvals.get_pending()
    proposal["name"] = "mutated-name"
    broker.approvals.resolve(request, True)
    result = await task
    assert result["added"] is False
    assert "invalid-frozen-name" in result["reason"]
    lines = open(broker.config.logs_path).read().splitlines()
    events = [json.loads(line) for line in lines]
    assert [event["decision"] for event in events] == ["escalated", "approved", "failed"]
    assert all(event["credential_requested"] == "policy.add:invalid-frozen-name" for event in events)
    assert "no-policy-body" not in "\n".join(lines)
