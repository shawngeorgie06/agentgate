# tests/test_db_cli.py
from __future__ import annotations

import textwrap

from broker.config import Config
from broker.db_resource_store import DbResourceStore
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
        "DB_RESOURCES_PATH": str(tmp_path / "db.json"),
    })


def test_db_add_list_remove(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path)
    monkeypatch.setenv("AGENTGATE_DB_ADMIN_PASSWORD", "admin-pw")
    rc = commands.run([
        "db-add", "analytics-ro", "--host", "db", "--port", "5432",
        "--dbname", "analytics", "--admin-user", "agentgate_admin",
        "--grant", "SELECT:public.events,users",
    ], config=cfg, master_password="pw")
    assert rc == 0

    store = DbResourceStore(cfg.db_resources_path, "pw")
    res = store.get("analytics-ro")
    assert res.admin_password == "admin-pw"
    assert res.grants == [{"verb": "SELECT", "objects": ["public.events", "users"]}]

    assert commands.run(["db-list"], config=cfg, master_password="pw") == 0
    out = capsys.readouterr().out
    assert "analytics-ro" in out and "admin-pw" not in out  # password never printed

    assert commands.run(["db-remove", "analytics-ro"], config=cfg, master_password="pw") == 0
    assert DbResourceStore(cfg.db_resources_path, "pw").list_names() == []

    log = (tmp_path / "audit.log").read_text()
    assert '"action": "db-add"' in log and '"action": "db-remove"' in log
    assert "admin-pw" not in log


def test_db_add_rejects_bad_grant(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    monkeypatch.setenv("AGENTGATE_DB_ADMIN_PASSWORD", "admin-pw")
    rc = commands.run([
        "db-add", "bad", "--host", "db", "--port", "5432",
        "--dbname", "d", "--admin-user", "a",
        "--grant", "DROP:public.events",
    ], config=cfg, master_password="pw")
    assert rc == 2
    assert DbResourceStore(cfg.db_resources_path, "pw").list_names() == []
