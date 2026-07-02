import asyncio
import dataclasses
import pytest
import textwrap
from broker.agent_store import AgentStore
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
        "AGENTS_PATH": str(tmp_path / "agents.json"),
        "AGENTGATE_MASTER_PASSWORD": "pw",
    }
    cfg = Config.from_env(env)
    store = CredentialStore(cfg.credentials_path, "pw")
    store.store("anthropic-api-key", "sk-secret")
    agents = AgentStore(cfg.agents_path, "pw")
    keys = {name: agents.register(name) for name in ("claude-code", "evil")}
    broker = Broker(
        config=cfg,
        store=store,
        engine=PolicyEngine.from_file(cfg.policies_path),
        audit=AuditLogger(cfg.logs_path),
        approvals=ApprovalQueue(),
        agents=agents,
    )
    broker.keys = keys  # test convenience: agent keys issued at registration
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
async def test_auto_approve_returns_value(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    res = await broker.request_credential(
        "claude-code", broker.keys["claude-code"], "anthropic-api-key")
    assert res["granted"] is True
    assert res["value"] == "sk-secret"
    # The raw credential is the grant; no decorative bearer token accompanies it.
    assert "token" not in res


@pytest.mark.asyncio
async def test_unknown_agent_denied_without_escalation(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    res = await broker.request_credential("ghost", "any-key", "anthropic-api-key")
    assert res["granted"] is False
    assert res["value"] is None
    assert "agent" in res["reason"]
    # Unauthenticated callers never reach the operator.
    assert broker.approvals.pending_count() == 0
    log = (tmp_path / "audit.log").read_text()
    assert '"policy_matched": "unauthenticated"' in log
    assert '"decision": "denied"' in log


@pytest.mark.asyncio
async def test_wrong_agent_key_denied_even_for_privileged_name(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    # Claiming a name with an auto-approve policy is useless without its key.
    res = await broker.request_credential(
        "claude-code", broker.keys["evil"], "anthropic-api-key")
    assert res["granted"] is False
    assert res["value"] is None


@pytest.mark.asyncio
async def test_manual_mode_unauthenticated_never_pages_operator(tmp_path):
    from broker import state
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    state.write_mode(broker.config.state_path, "manual")
    res = await broker.request_credential("ghost", "bad-key", "anthropic-api-key")
    assert res["granted"] is False
    assert broker.approvals.pending_count() == 0


@pytest.mark.asyncio
async def test_unmatched_request_escalates_then_denied(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    # "evil" is registered (authenticated) but matches no auto-approve policy.
    task = asyncio.create_task(broker.request_credential(
        "evil", broker.keys["evil"], "anthropic-api-key"))
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
    task = asyncio.create_task(broker.request_credential(
        "claude-code", broker.keys["claude-code"], "anthropic-api-key"))
    await asyncio.sleep(0)
    pending = broker.approvals.get_pending()
    assert pending is not None
    broker.approvals.resolve(pending, True)
    res = await task
    assert res["granted"] is True
    assert res["value"] == "sk-secret"


@pytest.mark.asyncio
async def test_add_policy_always_escalates_and_shows_full_body(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    # Even in AUTO mode, policy.add must escalate.
    task = asyncio.create_task(broker.add_policy(
        "claude-code", broker.keys["claude-code"],
        {"name": "new", "agent": "x", "credential": "y", "auto_approve": True},
    ))
    await asyncio.sleep(0)
    pending = broker.approvals.get_pending()
    assert pending is not None
    # The operator prompt must carry the full policy body, not just its name —
    # otherwise they approve blind.
    assert '"agent": "x"' in pending.credential
    assert '"auto_approve": true' in pending.credential
    broker.approvals.resolve(pending, True)
    res = await task
    assert res["added"] is True
    # Both sides of the decision are audited.
    log = (tmp_path / "audit.log").read_text()
    assert '"credential_requested": "policy.add:new"' in log
    assert '"decision": "escalated"' in log
    assert '"decision": "approved"' in log


@pytest.mark.asyncio
async def test_add_policy_requires_authentication(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    res = await broker.add_policy(
        "ghost", "bad-key",
        {"name": "sneaky", "agent": "*", "credential": "*", "auto_approve": True},
    )
    assert res["added"] is False
    assert broker.approvals.pending_count() == 0
    log = (tmp_path / "audit.log").read_text()
    assert '"policy_matched": "unauthenticated"' in log


@pytest.mark.asyncio
async def test_add_policy_denial_is_audited(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    task = asyncio.create_task(broker.add_policy(
        "claude-code", broker.keys["claude-code"],
        {"name": "sneaky", "agent": "*", "credential": "*", "auto_approve": True},
    ))
    await asyncio.sleep(0)
    broker.approvals.resolve(broker.approvals.get_pending(), False)
    res = await task
    assert res["added"] is False
    log = (tmp_path / "audit.log").read_text()
    assert '"credential_requested": "policy.add:sneaky"' in log
    assert '"decision": "denied"' in log


@pytest.mark.asyncio
async def test_add_policy_never_outranks_existing_specific_policies(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    # A proposed catch-all must not jump ahead of existing specific policies.
    task = asyncio.create_task(broker.add_policy(
        "claude-code", broker.keys["claude-code"],
        {"name": "grab-all", "agent": "*", "credential": "anthropic-api-key",
         "auto_approve": False, "escalate": True},
    ))
    await asyncio.sleep(0)
    broker.approvals.resolve(broker.approvals.get_pending(), True)
    await task
    names = [p["name"] for p in broker.list_policies()]
    # Inserted above the trailing default-deny (so it is reachable) but below
    # the existing specific policy (so it cannot steal precedence).
    assert names == ["cc-anthropic", "grab-all", "default-deny"]
    decision = broker.engine.evaluate("claude-code", "anthropic-api-key")
    assert decision.policy_name == "cc-anthropic"


@pytest.mark.asyncio
async def test_add_policy_rejects_invalid_policy_without_corrupting_file(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    # Capture original file content before any mutation attempt.
    original_content = open(broker.config.policies_path, "r", encoding="utf-8").read()

    # Submit a malformed policy (missing required 'credential' field).
    task = asyncio.create_task(broker.add_policy(
        "claude-code", broker.keys["claude-code"],
        {"name": "bad", "agent": "x", "auto_approve": True},
    ))
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
    task = asyncio.create_task(broker.add_policy(
        "claude-code", broker.keys["claude-code"],
        {"name": "new", "agent": "x", "credential": "y", "auto_approve": True},
    ))
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
    # "evil" matches no auto-approve policy -> escalates; no operator resolves it.
    res = await broker.request_credential(
        "evil", broker.keys["evil"], "anthropic-api-key")
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
        "claude-code", broker.keys["claude-code"],
        {"name": "new", "agent": "x", "credential": "y", "auto_approve": True},
    )
    assert res["added"] is False
    after = open(broker.config.policies_path, "r", encoding="utf-8").read()
    assert before == after


@pytest.mark.asyncio
async def test_decrypt_failure_fails_closed_with_audit(tmp_path, monkeypatch):
    from broker.credential_store import CredentialDecryptionError
    broker = _make_broker(tmp_path, _AUTO_POLICY)

    def failing_retrieve(name):
        raise CredentialDecryptionError("wrong password or tampered store detail")
    monkeypatch.setattr(broker.store, "retrieve", failing_retrieve)

    res = await broker.request_credential(
        "claude-code", broker.keys["claude-code"], "anthropic-api-key")
    assert res["granted"] is False
    assert res["value"] is None
    # Internal detail never leaks to the agent.
    assert "tampered" not in res["reason"]
    log = (tmp_path / "audit.log").read_text()
    assert '"decision": "denied"' in log


@pytest.mark.asyncio
async def test_escalate_false_hard_denies_without_paging_operator(tmp_path):
    broker = _make_broker(tmp_path, """
        policies:
          - name: hard-deny-prod
            agent: "*"
            credential: prod-db-password
            auto_approve: false
            escalate: false
          - name: default-deny
            agent: "*"
            credential: "*"
            auto_approve: false
            escalate: true
    """)
    res = await broker.request_credential(
        "claude-code", broker.keys["claude-code"], "prod-db-password")
    assert res["granted"] is False
    assert "hard-deny-prod" in res["reason"]
    # No operator interruption: nothing pending in the approval queue.
    assert broker.approvals.pending_count() == 0
    log = (tmp_path / "audit.log").read_text()
    assert '"decision": "denied"' in log


@pytest.mark.asyncio
async def test_policy_file_edit_takes_effect_without_restart(tmp_path):
    import os
    import textwrap
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    # Hand-edit the policy file to revoke claude-code's auto-approval.
    pol = broker.config.policies_path
    open(pol, "w").write(textwrap.dedent("""
        policies:
          - name: default-deny
            agent: "*"
            credential: "*"
            auto_approve: false
            escalate: true
    """))
    os.utime(pol, (os.path.getmtime(pol) + 5, os.path.getmtime(pol) + 5))
    task = asyncio.create_task(broker.request_credential(
        "claude-code", broker.keys["claude-code"], "anthropic-api-key"))
    await asyncio.sleep(0.05)
    # The edited file must govern: the request now escalates instead of auto-granting.
    pending = broker.approvals.get_pending()
    assert pending is not None
    broker.approvals.resolve(pending, False)
    res = await task
    assert res["granted"] is False


@pytest.mark.asyncio
async def test_invalid_policy_edit_keeps_previous_policies(tmp_path):
    import os
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    pol = broker.config.policies_path
    open(pol, "w").write("policies: [broken : yaml")
    os.utime(pol, (os.path.getmtime(pol) + 5, os.path.getmtime(pol) + 5))
    # Last valid engine keeps serving; the auto-approve policy still applies.
    res = await broker.request_credential(
        "claude-code", broker.keys["claude-code"], "anthropic-api-key")
    assert res["granted"] is True


def test_status_reports_mode_and_counts(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    s = broker.status()
    assert s["mode"] in ("auto", "manual")
    assert s["policies"] == 2
    assert s["requests"] == 0
    assert s["escalated"] == 0
    assert "uptime_seconds" in s
