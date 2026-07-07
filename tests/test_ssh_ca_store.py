from __future__ import annotations

import json

import pytest

from broker.ssh_ca_store import SshCaExistsError, SshCaStore


def test_initialize_returns_public_line_and_persists(tmp_path):
    store = SshCaStore(str(tmp_path / "ca.json"), "pw")
    pub = store.initialize()
    assert pub.startswith("ssh-ed25519 ")
    assert store.is_initialized()
    assert store.public_line() == pub
    pem = store.load_private_pem()
    assert pem.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    # A second store instance (fresh process) sees the same CA.
    again = SshCaStore(str(tmp_path / "ca.json"), "pw")
    assert again.load_private_pem() == pem


def test_private_key_is_encrypted_on_disk(tmp_path):
    path = tmp_path / "ca.json"
    SshCaStore(str(path), "pw").initialize()
    raw = path.read_text()
    assert "PRIVATE KEY" not in raw  # ciphertext only
    assert "ssh-ed25519 " in raw     # public line stays readable


def test_initialize_twice_refuses(tmp_path):
    store = SshCaStore(str(tmp_path / "ca.json"), "pw")
    store.initialize()
    with pytest.raises(SshCaExistsError):
        store.initialize()


def test_load_before_initialize_raises_keyerror(tmp_path):
    store = SshCaStore(str(tmp_path / "ca.json"), "pw")
    assert not store.is_initialized()
    with pytest.raises(KeyError):
        store.load_private_pem()
    with pytest.raises(KeyError):
        store.public_line()
