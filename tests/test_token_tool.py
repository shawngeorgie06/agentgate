from __future__ import annotations

import textwrap

import pytest
from fastmcp import Client

from broker import oauth
from broker.approval import ApprovalQueue
from broker.audit import AuditLogger
from broker.config import Config
from broker.connection_store import Connection, ConnectionStore
from broker.credential_store import CredentialStore
from broker.mcp_server import Broker, build_mcp
from broker.policy_engine import PolicyEngine


async def test_token_request_tool_registered_and_grants(tmp_path, monkeypatch):
    pol = tmp_path / "policies.yaml"
    pol.write_text(textwrap.dedent("""
        policies:
          - name: cc-work
            agent: claude-code
            credential: work
            auto_approve: true
    """))
    env = {
        "POLICIES_PATH": str(pol), "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "CONNECTIONS_PATH": str(tmp_path / "connections.json"),
        "AGENTS_PATH": str(tmp_path / "agents.json"),
        "AGENTGATE_MASTER_PASSWORD": "pw",
    }
    cfg = Config.from_env(env)
    connections = ConnectionStore(cfg.connections_path, "pw")
    connections.store("work", Connection(
        provider="google", client_id="cid", client_secret="csec",
        refresh_token="rt", scopes=["openid"], created_at="2026-06-27T10:00:00"))

    async def fake_refresh(**kwargs):
        return {"access_token": "AT-tool", "expires_at": "2099-01-01T00:00:00", "scopes": ["openid"]}
    monkeypatch.setattr(oauth, "refresh_access_token", fake_refresh)

    from broker.agent_store import AgentStore
    agents = AgentStore(cfg.agents_path, "pw")
    key = agents.register("claude-code")
    broker = Broker(
        config=cfg, store=CredentialStore(cfg.credentials_path, "pw"),
        engine=PolicyEngine.from_file(cfg.policies_path),
        audit=AuditLogger(cfg.logs_path), approvals=ApprovalQueue(),
        connections=connections, agents=agents,
    )
    mcp = build_mcp(broker)
    async with Client(mcp) as client:
        tools = [t.name for t in await client.list_tools()]
        # MCP spec tool-name pattern (^[a-zA-Z0-9_-]{1,64}$) forbids dots.
        import re
        assert all(re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", t) for t in tools)
        assert "token_request" in tools
        res = await client.call_tool("token_request", {
            "agent": "claude-code", "agent_key": key, "connection": "work"})
        assert res.data["granted"] is True
        assert res.data["access_token"] == "AT-tool"
