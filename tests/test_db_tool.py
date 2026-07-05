from __future__ import annotations

import re
import textwrap

import pytest
from fastmcp import Client

from broker import db_broker
from broker.agent_store import AgentStore
from broker.approval import ApprovalQueue
from broker.audit import AuditLogger
from broker.config import Config
from broker.credential_store import CredentialStore
from broker.crypto import CryptoDecryptionError
from broker.db_resource_store import DbResource, DbResourceStore
from broker.mcp_server import Broker, build_mcp
from broker.policy_engine import PolicyEngine


class FakeExecutor:
    def __init__(self, run_raises=False):
        self.run_raises = run_raises
        self.calls = []

    async def run_admin(self, dsn, statements):
        if self.run_raises:
            raise RuntimeError("admin connection refused")
        self.calls.append((dsn, statements))

    async def list_expired_roles(self, dsn, pattern):
        return []

    async def drop_role(self, dsn, role):
        pass


def _wire(tmp_path, run_raises=False):
    pol = tmp_path / "policies.yaml"
    pol.write_text(textwrap.dedent("""
        policies:
          - name: cc-analytics
            agent: claude-code
            credential: analytics-ro
            auto_approve: true
          - name: default-deny
            agent: "*"
            credential: "*"
            auto_approve: false
            escalate: true
    """))
    cfg = Config.from_env({
        "POLICIES_PATH": str(pol), "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTS_PATH": str(tmp_path / "agents.json"),
        "DB_RESOURCES_PATH": str(tmp_path / "db.json"),
    })
    agents = AgentStore(cfg.agents_path, "pw")
    key = agents.register("claude-code")
    resources = DbResourceStore(cfg.db_resources_path, "pw")
    resources.store(DbResource(
        name="analytics-ro", host="db", port=5432, dbname="analytics",
        admin_user="agentgate_admin", admin_password="admin-pw",
        grants=[{"verb": "SELECT", "objects": ["public.events"]}],
        created_at="2026-07-02T10:00:00+00:00",
    ))
    broker = Broker(
        config=cfg, store=CredentialStore(cfg.credentials_path, "pw"),
        engine=PolicyEngine.from_file(cfg.policies_path),
        audit=AuditLogger(cfg.logs_path), approvals=ApprovalQueue(),
        agents=agents, db_resources=resources, db_executor=FakeExecutor(run_raises),
    )
    return broker, key, cfg, tmp_path


async def test_db_credential_request_grants_and_audits(tmp_path):
    broker, key, cfg, tp = _wire(tmp_path)
    res = await broker.request_db_credential("claude-code", key, "analytics-ro")
    assert res["granted"] is True
    assert res["username"].startswith("agentgate_")
    assert res["password"]
    assert res["host"] == "db" and res["dbname"] == "analytics"
    log = (tp / "audit.log").read_text()
    assert res["password"] not in log          # password never audited
    assert '"username": "agentgate_' in log     # username IS audited
    assert '"decision": "approved"' in log


async def test_db_credential_request_unknown_agent_denied(tmp_path):
    broker, key, cfg, tp = _wire(tmp_path)
    res = await broker.request_db_credential("ghost", "bad", "analytics-ro")
    assert res["granted"] is False
    assert res["password"] is None
    assert broker.approvals.pending_count() == 0


async def test_db_credential_request_unknown_resource_denied(tmp_path):
    broker, key, cfg, tp = _wire(tmp_path)
    # 'nope' matches default-deny -> escalate -> approve -> resource missing -> fail closed.
    import asyncio
    task = asyncio.create_task(broker.request_db_credential("claude-code", key, "nope"))
    await asyncio.sleep(0.05)
    broker.approvals.resolve(broker.approvals.get_pending(), True)
    res = await task
    assert res["granted"] is False
    assert "nope" in res["reason"]


async def test_db_credential_request_mint_failure_fails_closed(tmp_path):
    broker, key, cfg, tp = _wire(tmp_path, run_raises=True)
    res = await broker.request_db_credential("claude-code", key, "analytics-ro")
    assert res["granted"] is False
    assert res["password"] is None
    assert "admin connection refused" not in res["reason"]  # generic reason only
    log = (tp / "audit.log").read_text()
    assert '"decision": "denied"' in log


class _CorruptResourceStore:
    """Stands in for a DbResourceStore whose backing file is tampered/corrupt:
    .get() raises broker.crypto.CryptoDecryptionError (NOT KeyError)."""

    def get(self, name):
        raise CryptoDecryptionError("SENSITIVE_DECRYPT_FAILURE_DETAIL")


async def test_db_credential_request_decryption_failure_fails_closed(tmp_path):
    broker, key, cfg, tp = _wire(tmp_path)
    broker.db_resources = _CorruptResourceStore()
    res = await broker.request_db_credential("claude-code", key, "analytics-ro")
    assert res["granted"] is False
    assert res["host"] is None
    assert res["port"] is None
    assert res["dbname"] is None
    assert res["username"] is None
    assert res["password"] is None
    assert res["expires_at"] is None
    assert "SENSITIVE_DECRYPT_FAILURE_DETAIL" not in res["reason"]
    log = (tp / "audit.log").read_text()
    assert '"decision": "denied"' in log
    assert "SENSITIVE_DECRYPT_FAILURE_DETAIL" not in log


async def test_tool_registered_and_spec_compliant(tmp_path):
    broker, key, cfg, tp = _wire(tmp_path)
    mcp = build_mcp(broker)
    async with Client(mcp) as client:
        names = [t.name for t in await client.list_tools()]
        assert "db_credential_request" in names
        assert all(re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", n) for n in names)
        res = await client.call_tool("db_credential_request", {
            "agent": "claude-code", "agent_key": key, "resource": "analytics-ro"})
        assert res.data["granted"] is True
