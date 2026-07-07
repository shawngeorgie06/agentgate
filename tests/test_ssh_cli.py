from __future__ import annotations

import textwrap

from broker.config import Config
from broker.ssh_ca_store import SshCaStore
from broker.ssh_resource_store import SshResourceStore
from cli import commands


def _cfg(tmp_path):
    (tmp_path / "p.yaml").write_text(textwrap.dedent("""
        policies:
          - name: d
            agent: "*"
            credential: "*"
            auto_approve: false
            escalate: true
    """))
    return Config.from_env({
        "POLICIES_PATH": str(tmp_path / "p.yaml"),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTS_PATH": str(tmp_path / "agents.json"),
        "SSH_CA_PATH": str(tmp_path / "ssh_ca.json"),
        "SSH_RESOURCES_PATH": str(tmp_path / "ssh.json"),
    })


def test_ssh_ca_init_and_pub(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    assert commands.run(["ssh-ca-init"], config=cfg, master_password="pw") == 0
    out = capsys.readouterr().out
    assert "ssh-ed25519 " in out
    assert "TrustedUserCAKeys" in out  # setup instructions printed
    assert "PRIVATE KEY" not in out

    assert commands.run(["ssh-ca-pub"], config=cfg, master_password="pw") == 0
    out = capsys.readouterr().out
    assert out.strip().startswith("ssh-ed25519 ")

    log = (tmp_path / "audit.log").read_text()
    assert '"action": "ssh-ca-init"' in log
    assert "PRIVATE KEY" not in log


def test_ssh_ca_init_twice_refuses(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    assert commands.run(["ssh-ca-init"], config=cfg, master_password="pw") == 0
    capsys.readouterr()
    pem_before = SshCaStore(cfg.ssh_ca_path, "pw").load_private_pem()
    assert commands.run(["ssh-ca-init"], config=cfg, master_password="pw") == 1
    # Existing CA untouched.
    assert SshCaStore(cfg.ssh_ca_path, "pw").load_private_pem() == pem_before


def test_ssh_ca_pub_before_init_fails(tmp_path):
    cfg = _cfg(tmp_path)
    assert commands.run(["ssh-ca-pub"], config=cfg, master_password="pw") == 1


def test_ssh_add_list_remove(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    rc = commands.run([
        "ssh-add", "web-1", "--host", "10.0.0.5", "--port", "22",
        "--principal", "deploy", "--force-command", "systemctl restart myapp",
    ], config=cfg, master_password="pw")
    assert rc == 0

    res = SshResourceStore(cfg.ssh_resources_path, "pw").get("web-1")
    assert res.principal == "deploy"
    assert res.force_command == "systemctl restart myapp"

    assert commands.run(["ssh-list"], config=cfg, master_password="pw") == 0
    out = capsys.readouterr().out
    assert "web-1" in out and "deploy" in out

    assert commands.run(["ssh-remove", "web-1"], config=cfg, master_password="pw") == 0
    assert SshResourceStore(cfg.ssh_resources_path, "pw").list_names() == []

    log = (tmp_path / "audit.log").read_text()
    assert '"action": "ssh-add"' in log and '"action": "ssh-remove"' in log


def test_ssh_add_without_force_command(tmp_path):
    cfg = _cfg(tmp_path)
    rc = commands.run([
        "ssh-add", "web-2", "--host", "h", "--port", "22", "--principal", "deploy",
    ], config=cfg, master_password="pw")
    assert rc == 0
    assert SshResourceStore(cfg.ssh_resources_path, "pw").get("web-2").force_command is None


def test_ssh_add_rejects_bad_principal(tmp_path):
    cfg = _cfg(tmp_path)
    rc = commands.run([
        "ssh-add", "bad", "--host", "h", "--port", "22", "--principal", "Root",
    ], config=cfg, master_password="pw")
    assert rc == 2
    assert SshResourceStore(cfg.ssh_resources_path, "pw").list_names() == []
    # No audit row for a rejected add.
    log_path = tmp_path / "audit.log"
    log_text = log_path.read_text() if log_path.exists() else ""
    assert '"action": "ssh-add"' not in log_text


def test_ssh_remove_unknown_fails(tmp_path):
    cfg = _cfg(tmp_path)
    assert commands.run(["ssh-remove", "nope"], config=cfg, master_password="pw") == 1
    log_path = tmp_path / "audit.log"
    log_text = log_path.read_text() if log_path.exists() else ""
    assert '"action": "ssh-remove"' not in log_text
