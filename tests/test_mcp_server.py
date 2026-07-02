import asyncio
import dataclasses
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
    assert res["value"] == "sk-secret"
    # The raw credential is the grant; no decorative bearer token accompanies it.
    assert "token" not in res


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


@pytest.mark.asyncio
async def test_add_policy_rejects_invalid_policy_without_corrupting_file(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    # Capture original file content before any mutation attempt.
    original_content = open(broker.config.policies_path, "r", encoding="utf-8").read()

    # Submit a malformed policy (missing required 'credential' field).
    task = asyncio.create_task(broker.add_policy({
        "name": "bad", "agent": "x", "auto_approve": True,
    }))
    await asyncio.sleep(0)
    pending = broker.approvals.get_pending()
    assert pending is not None
    broker.approvals.resolve(pending, True)
    res = await task

    assert res["added"] is False
    # File must be byte-for-byte unchanged.
    assert open(broker.config.policies_path, "r", encoding="utf-8").read() == original_content
    # Engine must still work: returns the original 2 policies.
    assert len(broker.list_policies()) == 2


@pytest.mark.asyncio
async def test_add_policy_persists_valid_policy(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    task = asyncio.create_task(broker.add_policy({
        "name": "new", "agent": "x", "credential": "y", "auto_approve": True,
    }))
    await asyncio.sleep(0)
    pending = broker.approvals.get_pending()
    assert pending is not None
    broker.approvals.resolve(pending, True)
    res = await task

    assert res["added"] is True
    names = [p["name"] for p in broker.list_policies()]
    assert "new" in names
    decision = broker.engine.evaluate("x", "y")
    assert decision.policy_name == "new"


@pytest.mark.asyncio
async def test_escalation_times_out_and_denies(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    broker.config = dataclasses.replace(broker.config, escalation_timeout_seconds=0.01)
    # "evil" agent doesn't match the auto-approve policy -> escalates; no operator resolves it.
    res = await broker.request_credential("evil", "anthropic-api-key")
    assert res["granted"] is False
    assert res["value"] is None
    log = (tmp_path / "audit.log").read_text()
    assert '"decision": "expired"' in log


@pytest.mark.asyncio
async def test_add_policy_times_out_without_modifying_file(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    broker.config = dataclasses.replace(broker.config, escalation_timeout_seconds=0.01)
    before = open(broker.config.policies_path, "r", encoding="utf-8").read()
    res = await broker.add_policy(
        {"name": "new", "agent": "x", "credential": "y", "auto_approve": True}
    )
    assert res["added"] is False
    after = open(broker.config.policies_path, "r", encoding="utf-8").read()
    assert before == after


def test_status_reports_mode_and_counts(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    s = broker.status()
    assert s["mode"] in ("auto", "manual")
    assert s["policies"] == 2
    assert s["requests"] == 0
    assert s["escalated"] == 0
    assert "uptime_seconds" in s
