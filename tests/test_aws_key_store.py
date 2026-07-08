from __future__ import annotations

import pytest

from broker.aws_key_store import AwsBrokerKey, AwsKeyStore


def test_set_load_roundtrip(tmp_path):
    store = AwsKeyStore(str(tmp_path / "k.json"), "pw")
    assert not store.is_set()
    store.set("AKIA_ID", "the-secret")
    assert store.is_set()
    key = store.load()
    assert isinstance(key, AwsBrokerKey)
    assert key.access_key_id == "AKIA_ID"
    assert key.secret_access_key == "the-secret"
    # Fresh instance (new process) decrypts the same secret.
    assert AwsKeyStore(str(tmp_path / "k.json"), "pw").load().secret_access_key == "the-secret"


def test_secret_is_encrypted_on_disk(tmp_path):
    path = tmp_path / "k.json"
    AwsKeyStore(str(path), "pw").set("AKIA_ID", "SENSITIVE_SECRET")
    raw = path.read_text()
    assert "SENSITIVE_SECRET" not in raw
    assert "AKIA_ID" in raw  # access key id is not secret


def test_set_overwrite_allowed(tmp_path):
    # Key rotation is routine — unlike an SSH CA, overwriting is permitted.
    store = AwsKeyStore(str(tmp_path / "k.json"), "pw")
    store.set("AKIA_1", "s1")
    store.set("AKIA_2", "s2")
    assert store.load().access_key_id == "AKIA_2"
    assert store.load().secret_access_key == "s2"


def test_load_before_set_raises_keyerror(tmp_path):
    with pytest.raises(KeyError):
        AwsKeyStore(str(tmp_path / "k.json"), "pw").load()


def test_secret_not_in_repr():
    assert "SENSITIVE" not in repr(AwsBrokerKey(access_key_id="AKIA", secret_access_key="SENSITIVE"))
