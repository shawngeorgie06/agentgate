from __future__ import annotations

import json
import textwrap

import pytest

from broker import oauth
from broker.approval import ApprovalQueue
from broker.audit import AuditLogger
from broker.config import Config
from broker.connection_store import Connection, ConnectionStore
from broker.mcp_server import Broker
from broker.policy_engine import PolicyEngine


def _make_broker(tmp_path, policy_body, monkeypatch):
    pol = tmp_path / "policies.yaml"
    pol.write_text(textwrap.dedent(policy_body))
    env = {
        "POLICIES_PATH": str(pol),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "CONNECTIONS_PATH": str(tmp_path / "connections.json"),
        "AGENTGATE_MASTER_PASSWORD": "pw",
    }
    cfg = Config.from_env(env)
    connections = ConnectionStore(cfg.connections_path, "pw")
    connections.store("work", Connection(
        provider="google", client_id="cid", client_secret="csec",
        refresh_token="rt", scopes=["openid", "email"], created_at="2026-06-27T10:00:00",
    ))
    # Stub the network refresh so no real HTTP happens.
    async def fake_refresh(**kwargs):
        return {"access_token": "AT-fresh", "expires_at": "2099-01-01T00:00:00",
                "scopes": ["openid", "email"]}
    monkeypatch.setattr(oauth, "refresh_access_token", fake_refresh)

    from broker.credential_store import CredentialStore
    broker = Broker(
        config=cfg,
        store=CredentialStore(cfg.credentials_path, "pw"),
        engine=PolicyEngine.from_file(cfg.policies_path),
        audit=AuditLogger(cfg.logs_path),
        approvals=ApprovalQueue(),
        connections=connections,
    )
    return broker, tmp_path


_AUTO = """
    policies:
      - name: cc-work
        agent: claude-code
        credential: work
        auto_approve: true
      - name: default-deny
        agent: "*"
        credential: "*"
        auto_approve: false
        escalate: true
"""


async def test_auto_approve_mints_token(tmp_path, monkeypatch):
    broker, _ = _make_broker(tmp_path, _AUTO, monkeypatch)
    res = await broker.request_token("claude-code", "work")
    assert res["granted"] is True
    assert res["access_token"] == "AT-fresh"
    assert res["scopes"] == ["openid", "email"]


async def test_unknown_connection_denied(tmp_path, monkeypatch):
    import asyncio
    broker, _ = _make_broker(tmp_path, _AUTO, monkeypatch)
    # 'nonexistent' hits default-deny -> escalate; resolve as approved,
    # then the missing connection makes the grant fail closed.
    task = asyncio.ensure_future(broker.request_token("claude-code", "nonexistent"))
    await asyncio.sleep(0.05)
    p = broker.approvals.get_pending()
    broker.approvals.resolve(p, True)
    res = await task
    assert res["granted"] is False
    assert "nonexistent" in res["reason"]


async def test_audit_never_contains_secrets(tmp_path, monkeypatch):
    broker, tp = _make_broker(tmp_path, _AUTO, monkeypatch)
    await broker.request_token("claude-code", "work")
    log = (tp / "audit.log").read_text(encoding="utf-8")
    assert "AT-fresh" not in log   # access token value never logged
    assert "csec" not in log       # client secret never logged
    entry = json.loads(log.strip().splitlines()[-1])
    assert entry["decision"] == "approved"
    assert entry["scopes"] == ["openid", "email"]
