import textwrap
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


@pytest.mark.asyncio
async def test_reaper_loop_reaps_each_resource_once_then_cancels(tmp_path, monkeypatch):
    import asyncio
    from broker import main as m
    from broker.db_resource_store import DbResource, DbResourceStore

    cfg = Config.from_env({
        "POLICIES_PATH": str(tmp_path / "p.yaml"),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTS_PATH": str(tmp_path / "agents.json"),
        "DB_RESOURCES_PATH": str(tmp_path / "db.json"),
        "DB_REAP_INTERVAL_SECONDS": "1",
    })
    (tmp_path / "p.yaml").write_text(
        'policies:\n  - name: d\n    agent: "*"\n    credential: "*"\n'
        "    auto_approve: false\n    escalate: true\n")
    resources = DbResourceStore(cfg.db_resources_path, "pw")
    resources.store(DbResource(
        name="r", host="h", port=5432, dbname="d", admin_user="a",
        admin_password="pw", grants=[], created_at="2026-07-02T10:00:00+00:00"))

    reaped = []

    async def fake_reap(executor, resource):
        reaped.append(resource.name)
        return ["agentgate_dead"]
    monkeypatch.setattr(m.db_broker, "reap", fake_reap)

    broker = m.build_broker(cfg, "pw")
    # Drive one sweep quickly instead of waiting the full interval. `m.asyncio`
    # is the *same* module object this test imports, so the replacement must
    # close over `real_sleep` (captured before patching) rather than call
    # `asyncio.sleep` directly -- otherwise it recurses into itself. For the
    # same reason the test's own wait below uses `real_sleep`, not
    # `asyncio.sleep`, so it isn't sped up too and the reaper task gets a
    # real turn to run.
    real_sleep = asyncio.sleep
    monkeypatch.setattr(m.asyncio, "sleep", lambda _s: real_sleep(0))
    task = asyncio.create_task(m._reaper_loop(broker))
    await real_sleep(0.05)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    assert "r" in reaped
    log = (tmp_path / "audit.log").read_text()
    assert '"action": "db-reap"' in log


@pytest.mark.asyncio
async def test_reaper_loop_logs_non_sensitive_line_and_continues_on_failure(
    tmp_path, monkeypatch, capsys
):
    """One resource's .get() raises (simulating a corrupt/tampered store entry
    with the admin password embedded in the exception text). The reaper must
    still process the other resources, and must print ONLY the resource name
    and exception type to stderr -- never the exception text or the admin
    password."""
    import asyncio
    from broker import main as m
    from broker.db_resource_store import DbResource, DbResourceStore

    cfg = Config.from_env({
        "POLICIES_PATH": str(tmp_path / "p.yaml"),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTS_PATH": str(tmp_path / "agents.json"),
        "DB_RESOURCES_PATH": str(tmp_path / "db.json"),
        "DB_REAP_INTERVAL_SECONDS": "1",
    })
    (tmp_path / "p.yaml").write_text(
        'policies:\n  - name: d\n    agent: "*"\n    credential: "*"\n'
        "    auto_approve: false\n    escalate: true\n")
    resources = DbResourceStore(cfg.db_resources_path, "pw")
    resources.store(DbResource(
        name="broken", host="h", port=5432, dbname="d", admin_user="a",
        admin_password="super-secret-admin-pw", grants=[],
        created_at="2026-07-02T10:00:00+00:00"))
    resources.store(DbResource(
        name="healthy", host="h", port=5432, dbname="d", admin_user="a",
        admin_password="other-pw", grants=[], created_at="2026-07-02T10:00:00+00:00"))

    reaped = []
    real_get = DbResourceStore.get

    def flaky_get(self, name):
        if name == "broken":
            raise RuntimeError("connection refused to super-secret-admin-pw@h")
        return real_get(self, name)
    monkeypatch.setattr(DbResourceStore, "get", flaky_get)

    async def fake_reap(executor, resource):
        reaped.append(resource.name)
        return []
    monkeypatch.setattr(m.db_broker, "reap", fake_reap)

    broker = m.build_broker(cfg, "pw")
    real_sleep = asyncio.sleep
    monkeypatch.setattr(m.asyncio, "sleep", lambda _s: real_sleep(0))
    task = asyncio.create_task(m._reaper_loop(broker))
    await real_sleep(0.05)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert "healthy" in reaped
    assert "broken" not in reaped

    err = capsys.readouterr().err
    assert "'broken'" in err
    assert "RuntimeError" in err
    assert "super-secret-admin-pw" not in err
    assert "connection refused" not in err


def test_build_broker_wires_ssh_stores(tmp_path):
    from broker import main as m
    cfg = Config.from_env({
        "POLICIES_PATH": str(tmp_path / "p.yaml"),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTS_PATH": str(tmp_path / "agents.json"),
        "DB_RESOURCES_PATH": str(tmp_path / "db.json"),
        "SSH_CA_PATH": str(tmp_path / "ssh_ca.json"),
        "SSH_RESOURCES_PATH": str(tmp_path / "ssh.json"),
    })
    (tmp_path / "p.yaml").write_text(
        'policies:\n  - name: d\n    agent: "*"\n    credential: "*"\n'
        "    auto_approve: false\n    escalate: true\n")
    broker = m.build_broker(cfg, "pw")
    assert broker.ssh_resources is not None
    assert broker.ssh_ca is not None


def test_build_broker_wires_aws(tmp_path):
    from broker import main as m
    cfg = Config.from_env({
        "POLICIES_PATH": str(tmp_path / "p.yaml"),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTS_PATH": str(tmp_path / "agents.json"),
        "AWS_KEY_PATH": str(tmp_path / "aws_key.json"),
        "AWS_RESOURCES_PATH": str(tmp_path / "aws.json"),
    })
    (tmp_path / "p.yaml").write_text(
        'policies:\n  - name: d\n    agent: "*"\n    credential: "*"\n'
        "    auto_approve: false\n    escalate: true\n")
    broker = m.build_broker(cfg, "pw")
    assert broker.aws_resources is not None
    assert broker.aws_key is not None
    assert broker.aws_executor is not None
