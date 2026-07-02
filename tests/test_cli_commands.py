import textwrap
from broker.config import Config
from cli import commands


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
    })


def test_cred_store_list_delete(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path)
    monkeypatch.setenv("AGENTGATE_CRED_VALUE", "sk-secret")
    assert commands.run(["cred-store", "k"], config=cfg, master_password="pw") == 0
    assert commands.run(["cred-list"], config=cfg, master_password="pw") == 0
    out = capsys.readouterr().out
    assert "k" in out
    assert "sk-secret" not in out  # value never printed
    assert commands.run(["cred-delete", "k"], config=cfg, master_password="pw") == 0


def test_policy_validate_ok(tmp_path):
    cfg = _cfg(tmp_path)
    assert commands.run(["policy-validate"], config=cfg) == 0


def test_status_prints_mode(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    assert commands.run(["status"], config=cfg) == 0
    assert "auto" in capsys.readouterr().out.lower()


def test_cli_returns_nonzero_on_invalid_config(monkeypatch, capsys):
    # No injected config -> run() calls Config.from_env(), which reads os.environ.
    monkeypatch.setenv("OAUTH_REDIRECT_PORT", "notaport")
    rc = commands.run(["status"])  # config=None on purpose
    assert rc != 0
    err = capsys.readouterr().err
    assert "OAUTH_REDIRECT_PORT" in err
