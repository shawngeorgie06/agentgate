from __future__ import annotations

import io
import textwrap

from broker.aws_key_store import AwsKeyStore
from broker.aws_resource_store import AwsResourceStore
from broker.config import Config
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
        "AWS_KEY_PATH": str(tmp_path / "aws_key.json"),
        "AWS_RESOURCES_PATH": str(tmp_path / "aws.json"),
    })


def test_aws_key_set_from_env(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path)
    monkeypatch.setenv("AGENTGATE_AWS_SECRET_KEY", "the-secret")
    rc = commands.run(["aws-key-set", "AKIA_ID"], config=cfg, master_password="pw")
    assert rc == 0
    key = AwsKeyStore(cfg.aws_key_path, "pw").load()
    assert key.access_key_id == "AKIA_ID"
    assert key.secret_access_key == "the-secret"
    out = capsys.readouterr().out
    assert "the-secret" not in out
    log = (tmp_path / "audit.log").read_text()
    assert '"action": "aws-key-set"' in log
    assert "the-secret" not in log


def test_aws_key_set_rejects_empty_secret(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    monkeypatch.delenv("AGENTGATE_AWS_SECRET_KEY", raising=False)
    monkeypatch.setattr(commands.sys, "stdin", io.StringIO(""))
    monkeypatch.setattr(commands.sys.stdin, "isatty", lambda: False, raising=False)
    rc = commands.run(["aws-key-set", "AKIA_ID"], config=cfg, master_password="pw")
    assert rc == 2
    assert not AwsKeyStore(cfg.aws_key_path, "pw").is_set()
    log_path = tmp_path / "audit.log"
    if log_path.exists():
        assert '"action": "aws-key-set"' not in log_path.read_text()


def test_aws_add_list_remove(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    rc = commands.run([
        "aws-add", "s3-reader",
        "--role-arn", "arn:aws:iam::123456789012:role/agent-s3-reader",
        "--region", "us-east-1", "--external-id", "ext-1",
    ], config=cfg, master_password="pw")
    assert rc == 0
    res = AwsResourceStore(cfg.aws_resources_path, "pw").get("s3-reader")
    assert res.role_arn == "arn:aws:iam::123456789012:role/agent-s3-reader"
    assert res.region == "us-east-1"
    assert res.external_id == "ext-1"

    assert commands.run(["aws-list"], config=cfg, master_password="pw") == 0
    out = capsys.readouterr().out
    assert "s3-reader" in out and "us-east-1" in out

    assert commands.run(["aws-remove", "s3-reader"], config=cfg, master_password="pw") == 0
    assert AwsResourceStore(cfg.aws_resources_path, "pw").list_names() == []

    log = (tmp_path / "audit.log").read_text()
    assert '"action": "aws-add"' in log and '"action": "aws-remove"' in log


def test_aws_add_without_external_id(tmp_path):
    cfg = _cfg(tmp_path)
    rc = commands.run([
        "aws-add", "s3", "--role-arn", "arn:aws:iam::123456789012:role/r",
        "--region", "eu-west-1",
    ], config=cfg, master_password="pw")
    assert rc == 0
    assert AwsResourceStore(cfg.aws_resources_path, "pw").get("s3").external_id is None


def test_aws_add_rejects_bad_arn(tmp_path):
    cfg = _cfg(tmp_path)
    rc = commands.run([
        "aws-add", "bad", "--role-arn", "arn:aws:iam::123:role/r", "--region", "us-east-1",
    ], config=cfg, master_password="pw")
    assert rc == 2
    assert AwsResourceStore(cfg.aws_resources_path, "pw").list_names() == []
    log_path = tmp_path / "audit.log"
    if log_path.exists():
        assert '"action": "aws-add"' not in log_path.read_text()


def test_aws_remove_unknown_fails(tmp_path):
    cfg = _cfg(tmp_path)
    assert commands.run(["aws-remove", "nope"], config=cfg, master_password="pw") == 1
    log_path = tmp_path / "audit.log"
    if log_path.exists():
        assert '"action": "aws-remove"' not in log_path.read_text()
