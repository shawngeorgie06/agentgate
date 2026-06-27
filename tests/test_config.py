import pytest
from broker.config import Config, ConfigError


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


def test_escalation_timeout_clamps_negative_to_zero():
    cfg = Config.from_env({"ESCALATION_TIMEOUT_SECONDS": "-5"})
    assert cfg.escalation_timeout_seconds == 0


def test_config_error_is_a_valueerror():
    assert issubclass(ConfigError, ValueError)


def test_token_ttl_non_numeric_raises_naming_the_var():
    with pytest.raises(ConfigError) as exc:
        Config.from_env({"TOKEN_TTL_MINUTES": "abc"})
    assert "TOKEN_TTL_MINUTES" in str(exc.value)
    assert "abc" in str(exc.value)


def test_token_ttl_zero_raises():
    with pytest.raises(ConfigError):
        Config.from_env({"TOKEN_TTL_MINUTES": "0"})


def test_token_ttl_negative_raises():
    with pytest.raises(ConfigError):
        Config.from_env({"TOKEN_TTL_MINUTES": "-1"})


def test_token_ttl_valid_passes():
    assert Config.from_env({"TOKEN_TTL_MINUTES": "30"}).token_ttl_minutes == 30


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
    assert cfg.token_ttl_minutes == 60
    assert cfg.escalation_timeout_seconds == 0
    assert cfg.state_path  # non-empty
