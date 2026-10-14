"""Tests for the operator-owned Gmail connection lifecycle."""
import asyncio
import json

import pytest

from broker.integrations.gmail import Gmail, GmailError, TOKEN_NAME, INTERNAL_PREFIX
from broker.main import build_broker
from broker.connections import GmailConnection
from tests.test_gmail import FakeService
from tests.test_main import _cfg


ACCOUNT_NAME = INTERNAL_PREFIX + 'gmail-account'


class ProfileService(FakeService):
    def getProfile(self, **kwargs):
        self.calls.append(('users', 'getProfile', kwargs))
        return type('Request', (), {'execute': lambda self: {'emailAddress': 'owner@example.test'}})()


def connected(tmp_path):
    broker = build_broker(_cfg(tmp_path), 'pw')
    service = ProfileService()
    gmail = Gmail(broker.store, service_factory=lambda: service)
    broker.store.store(TOKEN_NAME, '{"refresh_token":"hidden-refresh"}')
    return broker, service, GmailConnection(broker, gmail, 'oauth-client.json')


def test_info_returns_stable_account_status_without_credentials(tmp_path):
    broker, _, connection = connected(tmp_path)

    info = connection.info()

    assert info == {
        'service': 'gmail', 'status': 'connected',
        'account': {'email': 'owner@example.test'}, 'reconnecting': False,
    }
    assert 'hidden-refresh' not in json.dumps(info)
    assert json.loads(broker.store.retrieve(ACCOUNT_NAME)) == {'email': 'owner@example.test'}


def test_disconnect_removes_oauth_and_metadata_and_blocks_cached_calls(tmp_path):
    broker, service, connection = connected(tmp_path)
    assert connection.info()['status'] == 'connected'
    connection.disconnect()

    assert TOKEN_NAME not in broker.store.list_names()
    assert ACCOUNT_NAME not in broker.store.list_names()
    with pytest.raises(GmailError, match='not connected'):
        connection.gmail.call('search', query='test')
    assert not any(call[1] == 'list' for call in service.calls)


def test_refresh_race_cannot_restore_deleted_oauth(tmp_path):
    broker = build_broker(_cfg(tmp_path), 'pw')
    broker.store.store(TOKEN_NAME, json.dumps({
        'token': 'old-access', 'refresh_token': 'old-refresh',
        'client_id': 'client', 'client_secret': 'client-secret',
    }))
    gmail = Gmail(broker.store)
    gmail._credentials = type('Creds', (), {
        'token': 'old-access', 'valid': False,
        'refresh': lambda self, request: setattr(self, 'valid', True),
        'to_json': lambda self: '{"refresh_token":"resurrected"}',
    })()
    gmail._service = object()
    connection = GmailConnection(broker, gmail, 'client.json')
    connection.disconnect()

    with pytest.raises(GmailError, match='not connected'):
        gmail.call('search', query='test')
    assert TOKEN_NAME not in broker.store.list_names()


def test_disconnect_waits_for_refresh_then_removes_its_rotated_token(tmp_path, monkeypatch):
    import threading
    from broker.integrations import gmail as gmail_module

    broker = build_broker(_cfg(tmp_path), 'pw')
    broker.store.store(TOKEN_NAME, json.dumps({
        'token': 'old-access', 'refresh_token': 'old-refresh',
        'client_id': 'client', 'client_secret': 'client-secret',
    }))
    entered_refresh = threading.Event()
    allow_refresh = threading.Event()

    class FakeCredentials:
        def __init__(self, **kwargs):
            self.valid = False
            self.token = 'old-access'
        def refresh(self, request):
            entered_refresh.set()
            assert allow_refresh.wait(2)
            self.valid = True
            self.token = 'new-access'
        def to_json(self):
            return '{"refresh_token":"rotated-refresh"}'

    monkeypatch.setattr(gmail_module, 'Credentials', FakeCredentials)
    monkeypatch.setattr(gmail_module, 'AuthorizedHttp', lambda *a, **k: object())
    monkeypatch.setattr(gmail_module, 'build', lambda *a, **k: ProfileService())
    gmail = Gmail(broker.store)
    connection = GmailConnection(broker, gmail, 'client.json')
    errors = []
    caller = threading.Thread(target=lambda: _capture_error(errors, gmail.call, 'account'))
    caller.start()
    assert entered_refresh.wait(1)
    disconnect_started = threading.Event()

    def disconnect():
        disconnect_started.set()
        connection.disconnect()

    remover = threading.Thread(target=disconnect)
    remover.start()
    assert disconnect_started.wait(1)
    allow_refresh.set()
    caller.join(2)
    remover.join(2)

    assert not caller.is_alive() and not remover.is_alive()
    assert not errors
    assert TOKEN_NAME not in broker.store.list_names()
    assert gmail._suspended is True


def _capture_error(errors, function, *args):
    try:
        function(*args)
    except Exception as exc:
        errors.append(exc)


@pytest.mark.asyncio
async def test_failed_reconnect_preserves_working_connection(tmp_path, monkeypatch):
    from broker.integrations import gmail as gmail_module
    broker, _, connection = connected(tmp_path)
    original = broker.store.retrieve(TOKEN_NAME)

    def fail_connect(client_file, capture_store):
        capture_store.store(TOKEN_NAME, '{"refresh_token":"staged-secret"}')
        raise GmailError('OAuth failed: provider-secret')

    monkeypatch.setattr(gmail_module, 'connect', fail_connect)
    result = connection.begin_reconnect()
    assert result['active'] is True
    async with asyncio.timeout(2):
        while connection.reconnect_status()['active']:
            await asyncio.sleep(0.01)

    status = connection.reconnect_status()
    assert status['state'] == 'failed'
    assert 'provider-secret' not in json.dumps(status)
    assert broker.store.retrieve(TOKEN_NAME) == original
    assert connection.info()['status'] == 'connected'


@pytest.mark.asyncio
async def test_successful_reconnect_commits_staged_oauth_and_clears_provider_cache(tmp_path, monkeypatch):
    from broker.integrations import gmail as gmail_module
    broker, _, connection = connected(tmp_path)
    connection.gmail._credentials = object()
    connection.gmail._service = object()

    def fake_connect(client_file, capture_store):
        capture_store.store(TOKEN_NAME, '{"refresh_token":"new-refresh"}')
        return 'new@example.test'

    monkeypatch.setattr(gmail_module, 'connect', fake_connect)
    connection.begin_reconnect()
    async with asyncio.timeout(2):
        while connection.reconnect_status()['active']:
            await asyncio.sleep(0.01)

    assert connection.reconnect_status()['state'] == 'completed'
    assert json.loads(broker.store.retrieve(TOKEN_NAME)) == {'refresh_token': 'new-refresh'}
    assert json.loads(broker.store.retrieve(ACCOUNT_NAME)) == {'email': 'new@example.test'}
    assert connection.gmail._credentials is None
    assert connection.gmail._service is None


@pytest.mark.asyncio
async def test_reconnect_rejects_duplicate_and_disconnect_prevents_commit(tmp_path, monkeypatch):
    from broker.integrations import gmail as gmail_module
    broker, _, connection = connected(tmp_path)
    # The browser OAuth call runs in a thread, so use a thread-safe gate.
    import threading
    entered_thread = threading.Event()
    release_thread = threading.Event()

    def slow_connect(client_file, capture_store):
        entered_thread.set()
        release_thread.wait(2)
        capture_store.store(TOKEN_NAME, '{"refresh_token":"too-late"}')
        return 'late@example.test'

    monkeypatch.setattr(gmail_module, 'connect', slow_connect)
    connection.begin_reconnect()
    assert await asyncio.to_thread(entered_thread.wait, 1)
    assert connection.begin_reconnect()['active'] is True
    connection.disconnect()
    release_thread.set()
    async with asyncio.timeout(2):
        while connection.reconnect_status()['active']:
            await asyncio.sleep(0.01)

    assert TOKEN_NAME not in broker.store.list_names()
    assert connection.reconnect_status()['state'] == 'failed'

@pytest.mark.asyncio
async def test_old_reconnect_cancellation_cannot_overwrite_new_job_and_close_cancels_current(tmp_path):
    broker, _, connection = connected(tmp_path)
    started = asyncio.Queue()
    canceled = set()

    async def held_reconnect(generation, job_generation):
        started.put_nowait(job_generation)
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            canceled.add(job_generation)
            raise

    connection._reconnect = held_reconnect
    first = connection.begin_reconnect()
    first_generation = await started.get()
    assert first['active'] is True

    connection.disconnect()
    second = connection.begin_reconnect()
    second_generation = await started.get()
    assert second_generation > first_generation
    await asyncio.sleep(0)
    assert connection.reconnect_status() == {'active': True, 'state': 'connecting'}

    await connection.close()
    assert second_generation in canceled
    assert connection.reconnect_status()['active'] is False
    assert connection.reconnect_status()['state'] == 'failed'


@pytest.mark.asyncio
async def test_close_waits_for_atomic_reconnect_commit_to_finish(tmp_path, monkeypatch):
    import threading
    from broker.integrations import gmail as gmail_module

    broker, _, connection = connected(tmp_path)
    connection.info()
    old_token = broker.store.retrieve(TOKEN_NAME)
    old_account = broker.store.retrieve(ACCOUNT_NAME)
    original_update = broker.store.update
    update_entered = threading.Event()
    release_update = threading.Event()
    commit_finished = threading.Event()
    original_commit = connection._commit_staged

    def staged_connect(client_file, capture_store):
        capture_store.store(TOKEN_NAME, '{"refresh_token":"staged-only"}')
        return 'replacement@example.test'

    def delayed_update(values, *, delete=()):
        if values.get(TOKEN_NAME) == '{"refresh_token":"staged-only"}':
            update_entered.set()
            assert release_update.wait(2)
        return original_update(values, delete=delete)

    def observed_commit(*args):
        try:
            return original_commit(*args)
        finally:
            commit_finished.set()

    monkeypatch.setattr(gmail_module, 'connect', staged_connect)
    broker.store.update = delayed_update
    connection._commit_staged = observed_commit
    connection.begin_reconnect()
    assert await asyncio.to_thread(update_entered.wait, 1)
    closing = asyncio.create_task(connection.close())
    await asyncio.sleep(0.02)
    assert not closing.done()
    release_update.set()
    await closing
    assert await asyncio.to_thread(commit_finished.wait, 1)

    # The provider lock makes the ordering unambiguous: installation that already
    # owns the lock completes as one transaction before shutdown fences commits.
    assert json.loads(broker.store.retrieve(TOKEN_NAME)) == {'refresh_token':'staged-only'}
    assert json.loads(broker.store.retrieve(ACCOUNT_NAME)) == {'email':'replacement@example.test'}
    assert broker.store.retrieve(TOKEN_NAME) != old_token
    assert broker.store.retrieve(ACCOUNT_NAME) != old_account

def test_profile_metadata_write_finishes_before_disconnect_removes_it(tmp_path, monkeypatch):
    import threading
    broker, _, connection = connected(tmp_path)
    writing = threading.Event()
    release = threading.Event()
    removed = threading.Event()
    original = broker.store.store
    def blocked_store(name, value):
        if name == ACCOUNT_NAME:
            writing.set()
            assert release.wait(2)
        original(name,value)
    monkeypatch.setattr(broker.store,'store',blocked_store)
    reader = threading.Thread(target=connection.info)
    reader.start()
    assert writing.wait(1)
    def disconnect():
        connection.disconnect()
        removed.set()
    remover = threading.Thread(target=disconnect)
    remover.start()
    assert not removed.wait(.05)
    release.set()
    reader.join(2); remover.join(2)
    assert removed.is_set()
    assert ACCOUNT_NAME not in broker.store.list_names()
    assert TOKEN_NAME not in broker.store.list_names()
