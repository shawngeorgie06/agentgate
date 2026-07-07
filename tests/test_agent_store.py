from __future__ import annotations

import pytest

from broker.agent_store import AgentStore


def test_register_returns_key_and_verify_accepts_it(tmp_path):
    store = AgentStore(str(tmp_path / "agents.json"), "pw")
    key = store.register("claude-code")
    assert isinstance(key, str) and len(key) >= 32
    assert store.verify("claude-code", key) is True


def test_verify_rejects_wrong_key_and_unknown_agent(tmp_path):
    store = AgentStore(str(tmp_path / "agents.json"), "pw")
    key = store.register("claude-code")
    assert store.verify("claude-code", "not-the-key") is False
    assert store.verify("ghost", key) is False


def test_key_never_stored_on_disk(tmp_path):
    path = tmp_path / "agents.json"
    store = AgentStore(str(path), "pw")
    key = store.register("claude-code")
    raw = path.read_text(encoding="utf-8")
    assert key not in raw


def test_register_duplicate_raises(tmp_path):
    store = AgentStore(str(tmp_path / "agents.json"), "pw")
    store.register("claude-code")
    with pytest.raises(ValueError):
        store.register("claude-code")


def test_register_rejects_non_printable_or_empty_name(tmp_path):
    store = AgentStore(str(tmp_path / "agents.json"), "pw")
    with pytest.raises(ValueError):
        store.register("x\ny")
    with pytest.raises(ValueError):
        store.register("")
    assert store.list_names() == []
    assert store.verify("x\ny", "anything") is False
    # A normal name still registers fine after the rejected attempts.
    key = store.register("claude-code")
    assert store.verify("claude-code", key) is True


def test_delete_revokes(tmp_path):
    store = AgentStore(str(tmp_path / "agents.json"), "pw")
    key = store.register("claude-code")
    store.delete("claude-code")
    assert store.verify("claude-code", key) is False
    assert store.list_names() == []
    with pytest.raises(KeyError):
        store.delete("claude-code")


def test_verify_persists_across_instances(tmp_path):
    path = str(tmp_path / "agents.json")
    key = AgentStore(path, "pw").register("claude-code")
    assert AgentStore(path, "pw").verify("claude-code", key) is True


def test_wrong_master_password_fails_verification_not_crash(tmp_path):
    path = str(tmp_path / "agents.json")
    key = AgentStore(path, "pw").register("claude-code")
    # Wrong master password derives a different key: verification must simply
    # fail (deny), never grant or raise to the caller.
    assert AgentStore(path, "WRONG").verify("claude-code", key) is False
