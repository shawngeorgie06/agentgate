import pytest
from broker.credential_store import CredentialStore

def test_failed_write_keeps_existing_memory_and_disk(tmp_path, monkeypatch):
    path = tmp_path/'credentials.json'
    store = CredentialStore(str(path),'sample-password')
    store.store('token','old')
    monkeypatch.setattr(store,'_write',lambda _: (_ for _ in ()).throw(OSError('disk full')))
    with pytest.raises(OSError): store.store('token','candidate')
    assert store.retrieve('token') == 'old'
    assert CredentialStore(str(path),'sample-password').retrieve('token') == 'old'

def test_connection_pair_is_committed_together(tmp_path, monkeypatch):
    store = CredentialStore(str(tmp_path/'credentials.json'),'sample-password')
    store.update({'token':'old','account':'old-account'})
    monkeypatch.setattr(store,'_write',lambda _: (_ for _ in ()).throw(OSError('disk full')))
    with pytest.raises(OSError): store.update({'token':'candidate','account':'candidate-account'})
    assert store.retrieve('token') == 'old'
    assert store.retrieve('account') == 'old-account'
