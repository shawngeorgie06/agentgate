import hashlib
import sqlite3

import pytest

from broker.agent_registry import AgentRegistry, AgentRegistryError


def test_registry_keeps_only_hash_and_revocation_survives_restart(tmp_path):
    path = tmp_path / "agents.sqlite3"
    registry = AgentRegistry(path)
    created = registry.register("worker.one")
    token = created["token"]
    assert created["agent"]["status"] == "active"
    assert registry.authenticate(token)["id"] == "worker.one"
    assert token not in str(registry.list_agents())
    with sqlite3.connect(path) as db:
        stored = db.execute("SELECT token_hash FROM agents").fetchone()[0]
    assert stored == hashlib.sha256(token.encode()).hexdigest()
    assert token not in stored

    assert registry.revoke("worker.one")
    restarted = AgentRegistry(path)
    assert restarted.authenticate(token) is None
    assert restarted.list_agents()[0]["status"] == "revoked"
    with pytest.raises(AgentRegistryError):
        restarted.register("worker.one")


def test_import_is_idempotent_but_does_not_replace_or_reactivate(tmp_path):
    registry = AgentRegistry(tmp_path / "agents.sqlite3")
    token = "a" * 43
    agent = registry.import_token("bootstrap", token)
    assert agent["expires_at"] is None
    assert registry.import_token("bootstrap", token) == agent
    with pytest.raises(AgentRegistryError):
        registry.import_token("bootstrap", "b" * 43)
    registry.revoke("bootstrap")
    assert registry.import_token("bootstrap", token)["status"] == "revoked"
    assert registry.authenticate(token) is None


def test_registry_expires_and_validates_names_and_ttl(tmp_path):
    registry = AgentRegistry(tmp_path / "agents.sqlite3")
    agent = registry.register("short-lived", ttl_hours=1)
    with sqlite3.connect(tmp_path / "agents.sqlite3") as db:
        db.execute("UPDATE agents SET expires_at='2000-01-01T00:00:00Z'")
    assert registry.authenticate(agent["token"]) is None
    assert registry.list_agents()[0]["status"] == "expired"
    with pytest.raises(AgentRegistryError):
        registry.register("contains/slash")
    with pytest.raises(AgentRegistryError):
        registry.register("valid", ttl_hours=0)
    with pytest.raises(AgentRegistryError):
        registry.register("too-long", ttl_hours=8761)
    with pytest.raises(AgentRegistryError):
        registry.register("no-expiry", ttl_hours=None)
    for reserved in ("operator", "OPERATOR", "System"):
        with pytest.raises(AgentRegistryError):
            registry.register(reserved)


def test_registry_rejects_symlinks(tmp_path):
    target = tmp_path / "target.sqlite3"
    target.touch(mode=0o600)
    link = tmp_path / "link.sqlite3"
    link.symlink_to(target)
    with pytest.raises(AgentRegistryError):
        AgentRegistry(link)


def test_registry_file_is_created_private(tmp_path):
    path = tmp_path / "private.sqlite3"
    AgentRegistry(path)
    assert path.stat().st_mode & 0o777 == 0o600
