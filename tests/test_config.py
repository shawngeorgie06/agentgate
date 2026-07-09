import pytest
from broker.config import Config, ConfigError


def test_from_env_uses_defaults_when_unset():
    import os
    cfg = Config.from_env({})
    assert cfg.policies_path.endswith("policies.yaml")
    assert cfg.state_path.endswith("mode.json")
    assert cfg.logs_path.endswith("audit.log")
    assert cfg.credentials_path.endswith("credentials.json")
    assert cfg.master_password is None
    # Defaults anchor to a fixed per-user dir, never the CWD (running from a
    # different directory must not silently create fresh empty stores).
    for p in (cfg.policies_path, cfg.state_path, cfg.logs_path, cfg.credentials_path):
        assert os.path.isabs(p)
        assert ".agentgate" in p


def test_agentgate_home_overrides_default_base():
    import os
    cfg = Config.from_env({"AGENTGATE_HOME": os.path.join("srv", "ag")})
    assert cfg.policies_path == os.path.join("srv", "ag", "policies.yaml")
    assert cfg.agents_path == os.path.join("srv", "ag", "agents.json")


def test_from_env_reads_overrides():
    env = {
        "POLICIES_PATH": "/mnt/p.yaml",
        "STATE_PATH": "/mnt/s.json",
        "LOGS_PATH": "/mnt/a.log",
        "CREDENTIALS_PATH": "/mnt/c.json",
        "AGENTGATE_MASTER_PASSWORD": "hunter2",
    }
    cfg = Config.from_env(env)
    assert cfg.policies_path == "/mnt/p.yaml"
    assert cfg.state_path == "/mnt/s.json"
    assert cfg.logs_path == "/mnt/a.log"
    assert cfg.credentials_path == "/mnt/c.json"
    assert cfg.master_password == "hunter2"


def test_escalation_timeout_defaults_to_zero():
    assert Config.from_env({}).escalation_timeout_seconds == 0


def test_escalation_timeout_reads_override():
    cfg = Config.from_env({"ESCALATION_TIMEOUT_SECONDS": "30"})
    assert cfg.escalation_timeout_seconds == 30


def test_escalation_timeout_clamps_negative_to_zero():
    cfg = Config.from_env({"ESCALATION_TIMEOUT_SECONDS": "-5"})
    assert cfg.escalation_timeout_seconds == 0


def test_config_error_is_a_valueerror():
    assert issubclass(ConfigError, ValueError)


def test_escalation_non_numeric_raises_naming_the_var():
    with pytest.raises(ConfigError) as exc:
        Config.from_env({"ESCALATION_TIMEOUT_SECONDS": "soon"})
    assert "ESCALATION_TIMEOUT_SECONDS" in str(exc.value)


def test_escalation_negative_still_clamps_to_zero():
    assert Config.from_env({"ESCALATION_TIMEOUT_SECONDS": "-5"}).escalation_timeout_seconds == 0


def test_empty_path_raises_naming_the_var():
    with pytest.raises(ConfigError) as exc:
        Config.from_env({"STATE_PATH": ""})
    assert "STATE_PATH" in str(exc.value)


def test_defaults_are_all_valid():
    cfg = Config.from_env({})
    assert cfg.escalation_timeout_seconds == 0
    assert cfg.state_path  # non-empty


def test_oauth_defaults():
    from broker.config import Config
    env = {
        "POLICIES_PATH": "p", "STATE_PATH": "s", "LOGS_PATH": "l",
        "CREDENTIALS_PATH": "c",
    }
    cfg = Config.from_env(env)
    assert cfg.connections_path.endswith("connections.json")
    assert cfg.oauth_redirect_port == 8765


def test_oauth_redirect_port_override_and_validation():
    import pytest
    from broker.config import Config, ConfigError
    base = {
        "POLICIES_PATH": "p", "STATE_PATH": "s", "LOGS_PATH": "l",
        "CREDENTIALS_PATH": "c",
    }
    assert Config.from_env({**base, "OAUTH_REDIRECT_PORT": "9000"}).oauth_redirect_port == 9000
    with pytest.raises(ConfigError):
        Config.from_env({**base, "OAUTH_REDIRECT_PORT": "0"})
    with pytest.raises(ConfigError):
        Config.from_env({**base, "OAUTH_REDIRECT_PORT": "notaport"})


def test_db_defaults():
    cfg = Config.from_env({})
    assert cfg.db_resources_path.endswith("db_resources.json")
    assert cfg.db_cred_ttl_minutes == 15
    assert cfg.db_reap_interval_seconds == 30


def test_db_cred_ttl_must_be_positive():
    import pytest
    from broker.config import ConfigError
    with pytest.raises(ConfigError):
        Config.from_env({"DB_CRED_TTL_MINUTES": "0"})


def test_db_resources_path_follows_agentgate_home():
    import os
    cfg = Config.from_env({"AGENTGATE_HOME": os.path.join("srv", "ag")})
    assert cfg.db_resources_path == os.path.join("srv", "ag", "db_resources.json")


def test_ssh_defaults():
    cfg = Config.from_env({})
    assert cfg.ssh_ca_path.endswith("ssh_ca.json")
    assert cfg.ssh_resources_path.endswith("ssh_resources.json")
    assert cfg.ssh_cert_ttl_minutes == 15


def test_ssh_cert_ttl_must_be_positive():
    import pytest
    from broker.config import ConfigError
    with pytest.raises(ConfigError):
        Config.from_env({"SSH_CERT_TTL_MINUTES": "0"})
    with pytest.raises(ConfigError):
        Config.from_env({"SSH_CERT_TTL_MINUTES": "soon"})


def test_ssh_paths_follow_agentgate_home():
    import os
    cfg = Config.from_env({"AGENTGATE_HOME": os.path.join("srv", "ag")})
    assert cfg.ssh_ca_path == os.path.join("srv", "ag", "ssh_ca.json")
    assert cfg.ssh_resources_path == os.path.join("srv", "ag", "ssh_resources.json")


def test_aws_defaults():
    cfg = Config.from_env({})
    assert cfg.aws_key_path.endswith("aws_key.json")
    assert cfg.aws_resources_path.endswith("aws_resources.json")
    assert cfg.aws_cred_ttl_minutes == 15


def test_aws_cred_ttl_floor_is_15():
    import pytest
    from broker.config import ConfigError
    with pytest.raises(ConfigError):
        Config.from_env({"AWS_CRED_TTL_MINUTES": "14"})
    assert Config.from_env({"AWS_CRED_TTL_MINUTES": "15"}).aws_cred_ttl_minutes == 15
    assert Config.from_env({"AWS_CRED_TTL_MINUTES": "60"}).aws_cred_ttl_minutes == 60


def test_aws_paths_follow_agentgate_home():
    import os
    cfg = Config.from_env({"AGENTGATE_HOME": os.path.join("srv", "ag")})
    assert cfg.aws_key_path == os.path.join("srv", "ag", "aws_key.json")
    assert cfg.aws_resources_path == os.path.join("srv", "ag", "aws_resources.json")


def test_ssh_revocation_and_krl_paths_derive_from_home(tmp_path, monkeypatch):
    from broker.config import Config
    monkeypatch.setenv("AGENTGATE_HOME", str(tmp_path))
    cfg = Config.from_env()
    assert cfg.ssh_revocations_path == str(tmp_path / "ssh_revocations.json")
    assert cfg.ssh_krl_path == str(tmp_path / "ssh_krl")


def test_ssh_krl_path_overridable(monkeypatch):
    from broker.config import Config
    monkeypatch.setenv("SSH_KRL_PATH", "/etc/ssh/agentgate_krl")
    cfg = Config.from_env()
    assert cfg.ssh_krl_path == "/etc/ssh/agentgate_krl"
