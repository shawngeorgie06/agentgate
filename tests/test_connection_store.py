from __future__ import annotations

import pytest

from broker.connection_store import Connection, ConnectionStore


def _conn() -> Connection:
    return Connection(
        provider="google",
        client_id="cid-123",
        client_secret="csecret-xyz",
        refresh_token="rt-abc",
        scopes=["openid", "email"],
        created_at="2026-06-27T10:00:00",
    )


def test_store_and_get_roundtrip(tmp_path):
    store = ConnectionStore(str(tmp_path / "connections.json"), "pw")
    store.store("work", _conn())
    got = store.get("work")
    assert got.provider == "google"
    assert got.client_secret == "csecret-xyz"
    assert got.refresh_token == "rt-abc"
    assert got.scopes == ["openid", "email"]


def test_secrets_not_plaintext_on_disk(tmp_path):
    path = tmp_path / "connections.json"
    ConnectionStore(str(path), "pw").store("work", _conn())
    raw = path.read_text(encoding="utf-8")
    assert "csecret-xyz" not in raw
    assert "rt-abc" not in raw


def test_list_metadata_has_no_secrets(tmp_path):
    store = ConnectionStore(str(tmp_path / "connections.json"), "pw")
    store.store("work", _conn())
    meta = store.list_metadata()
    assert meta == [
        {"name": "work", "provider": "google", "scopes": ["openid", "email"],
         "created_at": "2026-06-27T10:00:00"}
    ]


def test_delete_and_missing(tmp_path):
    store = ConnectionStore(str(tmp_path / "connections.json"), "pw")
    store.store("work", _conn())
    store.delete("work")
    assert store.list_names() == []
    with pytest.raises(KeyError):
        store.get("work")
    with pytest.raises(KeyError):
        store.delete("work")
