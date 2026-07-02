import textwrap
from broker.config import Config
from broker import main as main_mod


def _cfg(tmp_path):
    pol = tmp_path / "policies.yaml"
    pol.write_text(textwrap.dedent("""
        policies:
          - name: default-deny
            agent: "*"
            credential: "*"
            auto_approve: false
            escalate: true
    """))
    return Config.from_env({
        "POLICIES_PATH": str(pol),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTGATE_MASTER_PASSWORD": "pw",
    })


def test_resolve_master_password_prefers_env(tmp_path):
    assert main_mod.resolve_master_password(_cfg(tmp_path)) == "pw"


def test_ensure_policies_file_bootstraps_default_deny(tmp_path):
    from broker.policy_engine import PolicyEngine
    cfg = Config.from_env({
        "POLICIES_PATH": str(tmp_path / "fresh" / "policies.yaml"),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTS_PATH": str(tmp_path / "agents.json"),
    })
    assert main_mod.ensure_policies_file(cfg) is True
    # The bootstrapped file is valid and denies+escalates everything.
    eng = PolicyEngine.from_file(cfg.policies_path)
    d = eng.evaluate("anyone", "anything")
    assert d.auto_approve is False and d.escalate is True
    # Second run: file exists, nothing overwritten.
    assert main_mod.ensure_policies_file(cfg) is False


def test_build_broker_constructs_with_policies(tmp_path):
    cfg = _cfg(tmp_path)
    broker = main_mod.build_broker(cfg, "pw")
    assert broker.status()["policies"] == 1


def test_format_status_line_contains_mode_and_counts(tmp_path):
    cfg = _cfg(tmp_path)
    broker = main_mod.build_broker(cfg, "pw")
    line = main_mod.format_status_line(broker)
    assert "AgentGate" in line
    assert "policies: 1" in line
    assert "requests: 0" in line
    assert "escalated: 0" in line
