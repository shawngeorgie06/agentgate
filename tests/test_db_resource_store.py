from __future__ import annotations

import pytest

from broker.crypto import CryptoDecryptionError
from broker.db_resource_store import DbResource, DbResourceStore


def _res() -> DbResource:
    return DbResource(
        name="analytics-ro", host="db.internal", port=5432, dbname="analytics",
        admin_user="agentgate_admin", admin_password="s3cret-admin",
        grants=[{"verb": "SELECT", "objects": ["public.events"]}],
        created_at="2026-07-02T10:00:00+00:00",
    )


def test_store_and_get_roundtrip(tmp_path):
    store = DbResourceStore(str(tmp_path / "db.json"), "pw")
    store.store(_res())
    got = store.get("analytics-ro")
    assert got.host == "db.internal"
    assert got.admin_password == "s3cret-admin"
    assert got.grants == [{"verb": "SELECT", "objects": ["public.events"]}]


def test_admin_password_encrypted_on_disk(tmp_path):
    path = tmp_path / "db.json"
    DbResourceStore(str(path), "pw").store(_res())
    raw = path.read_text(encoding="utf-8")
    assert "s3cret-admin" not in raw


def test_list_metadata_has_no_admin_password(tmp_path):
    store = DbResourceStore(str(tmp_path / "db.json"), "pw")
    store.store(_res())
    meta = store.list_metadata()
    assert meta == [{
        "name": "analytics-ro", "host": "db.internal", "port": 5432,
        "dbname": "analytics", "grants": [{"verb": "SELECT", "objects": ["public.events"]}],
        "created_at": "2026-07-02T10:00:00+00:00",
    }]


def test_delete_and_missing(tmp_path):
    store = DbResourceStore(str(tmp_path / "db.json"), "pw")
    store.store(_res())
    store.delete("analytics-ro")
    assert store.list_names() == []
    with pytest.raises(KeyError):
        store.get("analytics-ro")
    with pytest.raises(KeyError):
        store.delete("analytics-ro")


def test_wrong_password_fails_closed(tmp_path):
    path = str(tmp_path / "db.json")
    DbResourceStore(path, "pw").store(_res())
    with pytest.raises(CryptoDecryptionError):
        DbResourceStore(path, "WRONG").get("analytics-ro")
