import textwrap
import dataclasses
import pytest
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


def test_agents_path_defaults_beside_credentials_and_can_be_overridden(tmp_path):
    assert _cfg(tmp_path).agents_path == str(tmp_path / "agents.sqlite3")
    cfg = Config.from_env({
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTS_PATH": str(tmp_path / "custom.sqlite3"),
    })
    assert cfg.agents_path == str(tmp_path / "custom.sqlite3")


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


@pytest.mark.asyncio
@pytest.mark.parametrize('password, timeout, message', [
    (None, 1, 'AGENTGATE_MASTER_PASSWORD'),
    ('pw', 0, 'ESCALATION_TIMEOUT_SECONDS'),
])
async def test_headless_requires_password_and_timeout(tmp_path, monkeypatch, password, timeout, message):
    monkeypatch.setattr(main_mod, 'open_terminal', lambda: None)
    cfg = dataclasses.replace(_cfg(tmp_path), master_password=password, escalation_timeout_seconds=timeout)
    with pytest.raises(main_mod.ConfigError, match=message):
        await main_mod.run(cfg)

def test_broker_refuses_wrong_password_before_serving_connected_app(tmp_path):
    from broker.credential_store import CredentialStore
    cfg = _cfg(tmp_path)
    CredentialStore(cfg.credentials_path,'original-password').store('__agentgate:gmail-oauth','private-value')
    with pytest.raises(main_mod.ConfigError, match='unlock saved credentials') as error:
        main_mod.build_broker(cfg,'mistyped-password')
    assert 'private-value' not in str(error.value)
    assert 'original-password' not in str(error.value)
    assert 'mistyped-password' not in str(error.value)

@pytest.mark.parametrize('entry', [{}, {'nonce':'not-valid-base64','ciphertext':'invalid'}])
def test_broker_reports_damaged_encrypted_entry_without_traceback_details(tmp_path,entry):
    import json
    from broker.credential_store import CredentialStore
    cfg = _cfg(tmp_path)
    CredentialStore(cfg.credentials_path,'pw').store('private-name','private-value')
    with open(cfg.credentials_path) as stream: data=json.load(stream)
    data['credentials']['private-name']=entry
    with open(cfg.credentials_path,'w') as stream: json.dump(data,stream)
    with pytest.raises(main_mod.ConfigError,match='unlock saved credentials') as error:
        main_mod.build_broker(cfg,'pw')
    assert 'private-name' not in str(error.value)

def test_broker_reports_invalid_encryption_salt_safely(tmp_path):
    import json
    cfg=_cfg(tmp_path)
    with open(cfg.credentials_path,'w') as stream:
        json.dump({'salt':'AA==','credentials':{}},stream)
    with pytest.raises(main_mod.ConfigError,match='unlock saved credentials'):
        main_mod.build_broker(cfg,'pw')
