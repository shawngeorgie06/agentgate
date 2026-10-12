import dataclasses
import pytest
from broker import main
from tests.test_main import _cfg

@pytest.mark.asyncio
async def test_keychain_startup_uses_private_provider_without_terminal(tmp_path,monkeypatch):
    cfg=dataclasses.replace(_cfg(tmp_path),master_password=None,escalation_timeout_seconds=60)
    calls=[]
    def read_password(helper,path):
        calls.append((helper,path));return 'sample-private-unlock'
    monkeypatch.setattr('broker.mac_keychain.read_password',read_password)
    monkeypatch.setattr(main,'open_terminal',lambda: (_ for _ in ()).throw(AssertionError('must not open terminal')))
    class ReachedBuild(Exception): pass
    def build(config,password):
        assert password=='sample-private-unlock'
        raise ReachedBuild()
    monkeypatch.setattr(main,'build_broker',build)
    with pytest.raises(ReachedBuild):
        await main.run(cfg,keychain_helper='/sample/AgentGateKeychain')
    assert calls==[('/sample/AgentGateKeychain',cfg.credentials_path)]

@pytest.mark.asyncio
async def test_missing_keychain_password_fails_before_opening_store(tmp_path,monkeypatch):
    cfg=dataclasses.replace(_cfg(tmp_path),master_password=None,escalation_timeout_seconds=60)
    def missing(*args): raise main.ConfigError('Unlock AgentGate in the app first.')
    monkeypatch.setattr('broker.mac_keychain.read_password',missing)
    monkeypatch.setattr(main,'build_broker',lambda *_: (_ for _ in ()).throw(AssertionError('no store on failed unlock')))
    with pytest.raises(main.ConfigError,match='Unlock AgentGate'):
        await main.run(cfg,keychain_helper='/sample/AgentGateKeychain')

@pytest.mark.asyncio
async def test_credential_alias_uses_same_single_process_lock(tmp_path):
    from broker.credential_store import CredentialStore
    from broker.process_lock import CredentialProcessLock
    cfg=_cfg(tmp_path)
    CredentialStore(cfg.credentials_path,'pw').store('sample','sample-value')
    alias=tmp_path/'alias.json'
    alias.symlink_to(cfg.credentials_path)
    cfg=dataclasses.replace(cfg,credentials_path=str(alias))
    with CredentialProcessLock(str(tmp_path/'creds.json')+'.broker.lock'):
        with pytest.raises(main.ConfigError,match='already running'):
            await main.run(cfg)
