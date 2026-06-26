import asyncio
import pytest
import textwrap
from broker.config import Config
from broker.credential_store import CredentialStore
from broker.policy_engine import PolicyEngine
from broker.audit import AuditLogger
from broker.approval import ApprovalQueue
from broker.mcp_server import Broker


def _make_broker(tmp_path, policy_body):
    pol = tmp_path / "policies.yaml"
    pol.write_text(textwrap.dedent(policy_body))
    env = {
        "POLICIES_PATH": str(pol),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTGATE_MASTER_PASSWORD": "pw",
    }
    cfg = Config.from_env(env)
    store = CredentialStore(cfg.credentials_path, "pw")
    store.store("anthropic-api-key", "sk-secret")
    broker = Broker(
        config=cfg,
        store=store,
        engine=PolicyEngine.from_file(cfg.policies_path),
        audit=AuditLogger(cfg.logs_path),
        approvals=ApprovalQueue(),
    )
    return broker


_AUTO_POLICY = """
    policies:
      - name: cc-anthropic
        agent: claude-code
        credential: anthropic-api-key
        auto_approve: true
      - name: default-deny
        agent: "*"
        credential: "*"
        auto_approve: false
        escalate: true
"""


@pytest.mark.asyncio
async def test_auto_approve_returns_token_and_value(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    res = await broker.request_credential("claude-code", "anthropic-api-key")
    assert res["granted"] is True
    assert res["token"]
    assert res["value"] == "sk-secret"
    assert res["token_expiry"]


@pytest.mark.asyncio
async def test_unmatched_request_escalates_then_denied(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    task = asyncio.create_task(broker.request_credential("evil", "anthropic-api-key"))
    await asyncio.sleep(0)
    pending = broker.approvals.get_pending()
    assert pending is not None
    broker.approvals.resolve(pending, False)
    res = await task
    assert res["granted"] is False
    assert res["value"] is None


@pytest.mark.asyncio
async def test_manual_mode_escalates_even_for_auto_policy(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    from broker import state
    state.write_mode(broker.config.state_path, "manual")
    task = asyncio.create_task(broker.request_credential("claude-code", "anthropic-api-key"))
    await asyncio.sleep(0)
    pending = broker.approvals.get_pending()
    assert pending is not None
    broker.approvals.resolve(pending, True)
    res = await task
    assert res["granted"] is True
    assert res["value"] == "sk-secret"


@pytest.mark.asyncio
async def test_add_policy_always_escalates(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    # Even in AUTO mode, policy.add must escalate.
    task = asyncio.create_task(broker.add_policy({
        "name": "new", "agent": "x", "credential": "y", "auto_approve": True,
    }))
    await asyncio.sleep(0)
    pending = broker.approvals.get_pending()
    assert pending is not None
    broker.approvals.resolve(pending, True)
    res = await task
    assert res["added"] is True


def test_status_reports_mode_and_counts(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    s = broker.status()
    assert s["mode"] in ("auto", "manual")
    assert s["policies"] == 2
    assert s["requests"] == 0
    assert "uptime_seconds" in s
