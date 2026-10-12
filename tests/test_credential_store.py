import json
import pytest
from broker.credential_store import CredentialStore, CredentialDecryptionError


def test_store_and_retrieve_round_trip(tmp_path):
    path = tmp_path / "creds.json"
    store = CredentialStore(str(path), "master-pw")
    store.store("anthropic-api-key", "sk-ant-secret")
    assert store.retrieve("anthropic-api-key") == "sk-ant-secret"


def test_retrieve_missing_raises_keyerror(tmp_path):
    store = CredentialStore(str(tmp_path / "creds.json"), "pw")
    with pytest.raises(KeyError):
        store.retrieve("nope")


def test_delete_removes_credential(tmp_path):
    store = CredentialStore(str(tmp_path / "creds.json"), "pw")
    store.store("k", "v")
    store.delete("k")
    assert store.list_names() == []
    with pytest.raises(KeyError):
        store.delete("k")


def test_plaintext_never_on_disk(tmp_path):
    path = tmp_path / "creds.json"
    store = CredentialStore(str(path), "pw")
    store.store("k", "super-secret-value")
    raw = path.read_text()
    assert "super-secret-value" not in raw
    data = json.loads(raw)
    assert "salt" in data
    assert "nonce" in data["credentials"]["k"]
    assert "ciphertext" in data["credentials"]["k"]


def test_wrong_password_fails_to_decrypt(tmp_path):
    path = tmp_path / "creds.json"
    CredentialStore(str(path), "right-pw").store("k", "v")
    reopened = CredentialStore(str(path), "wrong-pw")
    with pytest.raises(CredentialDecryptionError):
        reopened.retrieve("k")


def test_salt_persists_across_instances(tmp_path):
    path = tmp_path / "creds.json"
    CredentialStore(str(path), "pw").store("k", "v")
    # New instance, same password, must decrypt existing data.
    assert CredentialStore(str(path), "pw").retrieve("k") == "v"


def test_store_uses_fresh_nonce_each_call(tmp_path):
    path = tmp_path / "creds.json"
    store = CredentialStore(str(path), "pw")
    store.store("k", "v")
    nonce1 = json.loads(path.read_text())["credentials"]["k"]["nonce"]
    store.store("k", "v")
    nonce2 = json.loads(path.read_text())["credentials"]["k"]["nonce"]
    assert nonce1 != nonce2


def test_concurrent_in_process_writes_preserve_credentials(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    store = CredentialStore(str(tmp_path / 'credentials.json'), 'pw')
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(lambda i: store.store(f'key-{i}', f'value-{i}'), range(12)))
    reopened = CredentialStore(str(tmp_path / 'credentials.json'), 'pw')
    for i in range(12):
        assert reopened.retrieve(f'key-{i}') == f'value-{i}'

def test_credential_rewrites_keep_private_file_permissions(tmp_path):
    import os,stat
    path=tmp_path/'creds.json'
    old=os.umask(0o022)
    try:
        store=CredentialStore(str(path),'pw')
        store.store('sample','value')
        assert stat.S_IMODE(path.stat().st_mode)==0o600
        store.store('sample','updated')
        assert stat.S_IMODE(path.stat().st_mode)==0o600
    finally: os.umask(old)
