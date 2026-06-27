from broker.config import Config


def test_from_env_uses_defaults_when_unset():
    cfg = Config.from_env({})
    assert cfg.policies_path.endswith("policies.yaml")
    assert cfg.state_path.endswith("mode.json")
    assert cfg.logs_path.endswith("audit.log")
    assert cfg.credentials_path.endswith("credentials.json")
    assert cfg.token_ttl_minutes == 60
    assert cfg.master_password is None


def test_from_env_reads_overrides():
    env = {
        "POLICIES_PATH": "/mnt/p.yaml",
        "STATE_PATH": "/mnt/s.json",
        "LOGS_PATH": "/mnt/a.log",
        "CREDENTIALS_PATH": "/mnt/c.json",
        "TOKEN_TTL_MINUTES": "15",
        "AGENTGATE_MASTER_PASSWORD": "hunter2",
    }
    cfg = Config.from_env(env)
    assert cfg.policies_path == "/mnt/p.yaml"
    assert cfg.state_path == "/mnt/s.json"
    assert cfg.logs_path == "/mnt/a.log"
    assert cfg.credentials_path == "/mnt/c.json"
    assert cfg.token_ttl_minutes == 15
    assert cfg.master_password == "hunter2"


def test_escalation_timeout_defaults_to_zero():
    assert Config.from_env({}).escalation_timeout_seconds == 0


def test_escalation_timeout_reads_override():
    cfg = Config.from_env({"ESCALATION_TIMEOUT_SECONDS": "30"})
    assert cfg.escalation_timeout_seconds == 30
