import asyncio
import inspect
import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from broker.imessage_bridge import MessagesBridge, MessagesBridgeError, PairingBridge, is_self_chat

PAIRED = 424242
GUID = 'iMessage;-;+15550100'
TEXT = 'private hello body'

# A tiny stand-in for `imsg rpc`. Behaviour is selected per test through CONFIG
# so no environment variables are needed (the bridge uses a minimal env).
FAKE_HELPER = r'''#!__PYTHON__
import json, os, signal, sys, time
CONFIG = json.loads(@CONFIG@)
LOG, MODE, PAIRED = CONFIG['log'], CONFIG['mode'], CONFIG['paired']
GUID = 'iMessage;-;+15550100'
chats_get = 0
subscriptions = 0

def log(entry):
    with open(LOG, 'a', encoding='utf-8') as handle:
        handle.write(json.dumps(entry) + '\n')

def emit(text):
    sys.stdout.write(text + '\n')
    sys.stdout.flush()

def reply(request_id, result=None, error=None):
    body = {'jsonrpc': '2.0', 'id': request_id}
    if error is not None:
        body['error'] = error
    else:
        body['result'] = result
    emit(json.dumps(body))

def message(rowid, **overrides):
    value = {'id': rowid, 'chat_id': PAIRED, 'guid': 'G%d' % rowid, 'chat_guid': GUID,
             'sender': '+15550100', 'text': 'hi', 'created_at': '2026-10-12T12:00:00Z',
             'is_from_me': False, 'is_group': False, 'participants': []}
    value.update(overrides)
    return value

def notify(value, subscription=7):
    emit(json.dumps({'jsonrpc': '2.0', 'method': 'message',
                     'params': {'subscription': subscription, 'message': value}}))

def overflow(subscription=7, resume=None):
    params = {'subscription': subscription, 'reason': 'buffer_limit_exceeded', 'terminal': True}
    if resume is not None:
        params['resume_after_rowid'] = resume
    emit(json.dumps({'jsonrpc': '2.0', 'method': 'watch.overflow', 'params': params}))

def chat_metadata():
    value = {'id': PAIRED, 'identifier': '+15550100', 'guid': GUID, 'name': '',
             'service': 'iMessage', 'is_group': False, 'participants': ['+15550100'],
             'account_login': 'P:+15550100'}
    if MODE == 'chat_group':
        value.update(is_group=True, guid='iMessage;+;chat123')
    if MODE == 'chat_sms':
        value['service'] = 'SMS'
    if MODE == 'chat_two':
        value['participants'] = ['+15550100', '+15550199']
    if MODE == 'chat_other_account':
        value['account_login'] = 'P:+15559999'
    return value

if MODE == 'ignore_term':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
log({'start': True, 'argv': sys.argv, 'env': dict(os.environ)})

for line in sys.stdin:
    try:
        request = json.loads(line)
    except ValueError:
        log({'bad_line': True})
        continue
    method, request_id = request.get('method'), request.get('id')
    log({'method': method, 'id': request_id, 'params': request.get('params')})
    if MODE == 'stray':
        reply('nobody-asked', {'stray': True})
    if method == 'initialize':
        reply(request_id, {'protocol_version': 1})
        if MODE == 'exit_after_init':
            sys.exit(0)
    elif method == 'chats.get':
        chats_get += 1
        if MODE == 'hang' and chats_get > 1:
            continue
        if MODE == 'error_rpc' and chats_get > 1:
            reply(request_id, error={'code': -32000, 'message': 'private text leak'})
            continue
        if MODE == 'oversize' and chats_get == 2:
            emit('x' * (1024 * 1024 + 100))
            continue
        reply(request_id, chat_metadata())
    elif method == 'chats.list':
        reply(request_id, {'chats': [{'id': PAIRED, 'guid': GUID}, {'id': 'nope'}, {'id': 0}]})
    elif method == 'messages.history':
        reply(request_id, {'messages': [
            message(201, is_from_me=True, text='/agent pair AG-TEST23'),
            message(202, is_from_me=False, text=None)]})
    elif method == 'messages.after':
        since = request['params']['since_rowid']
        if MODE == 'recover':
            reply(request_id, {'messages': [message(103), message(104, chat_id=PAIRED + 1)],
                               'next_rowid': 104, 'has_more': False})
        elif MODE == 'recover_pages':
            reply(request_id, {'messages': [], 'next_rowid': since + 1, 'has_more': True})
        elif MODE == 'recover_regress':
            reply(request_id, {'messages': [], 'next_rowid': since - 1, 'has_more': False})
        else:
            reply(request_id, {'messages': [], 'next_rowid': since, 'has_more': False})
    elif method == 'watch.subscribe':
        subscriptions += 1
        subscription = 7 if subscriptions == 1 else 8
        reply(request_id, {'subscription': subscription, 'buffer_limit': 64})
        if MODE == 'burst':
            for rowid in range(201, 206):
                notify(message(rowid))
        elif MODE == 'normal' and subscription == 7:
            emit('not json at all')
            emit('{"jsonrpc":"2.0","method":"message","params":"' + 'x' * (1024 * 1024 + 10) + '"}')
            emit('[1, 2]')
            notify(message(100, chat_id=PAIRED + 1))
            notify(message(101, created_at='2026-10-12T12:00:00'))
            notify(message(102, is_from_me='yes'))
            notify(message(103, text='hello ' + 'a' * 5000))
            notify(message(104, is_from_me=True, text='reply'))
            overflow(7, 104)
        elif MODE in ('recover', 'recover_pages', 'recover_regress', 'overflow_bad') and subscription == 7:
            notify(message(150), subscription=3)  # stale or foreign subscription: ignored
            notify(message(101))
            notify(message(102))
            overflow(7, None if MODE == 'overflow_bad' else 102)
            notify(message(106))  # stale: sent after a terminal overflow, must be dropped
        elif MODE == 'overflow_full' and subscription == 7:
            notify(message(101))
            notify(message(102))
            notify(message(103))
            overflow(7, 103)
        elif MODE == 'recover' and subscription == 8:
            notify(message(105), subscription=8)
    elif method == 'send':
        if MODE == 'hang':
            continue
        if MODE == 'send_32001':
            reply(request_id, error={'code': -32001, 'message': 'delivery unknown'})
        elif MODE == 'send_32004':
            reply(request_id, error={'code': -32004, 'message': 'mutation lane blocked'})
        elif MODE == 'slow_send':
            time.sleep(0.5)
            reply(request_id, {'ok': True})
        elif MODE == 'send_error':
            reply(request_id, error={'code': -32000, 'message': 'nope'})
        else:
            reply(request_id, {'ok': True})
    else:
        reply(request_id, error={'code': -32601, 'message': 'method not found'})
if MODE == 'ignore_term':
    time.sleep(3600)  # Runs only after stdin EOF from close(); SIGTERM is ignored, so close() must SIGKILL.
'''


def make_helper(tmp_path, mode='normal', mode_bits=0o700, name='imsg', directory=None):
    log = tmp_path / 'requests.jsonl'
    script = FAKE_HELPER.replace('__PYTHON__', sys.executable)
    script = script.replace('@CONFIG@', repr(json.dumps({'log': str(log), 'mode': mode, 'paired': PAIRED})))
    path = (directory or tmp_path) / name
    path.write_text(script)
    path.chmod(mode_bits)
    return path


def requests(tmp_path):
    log = tmp_path / 'requests.jsonl'
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines()]


def methods(tmp_path):
    return [entry['method'] for entry in requests(tmp_path) if 'method' in entry]


def params_of(tmp_path, method):
    return [e['params'] for e in requests(tmp_path) if e.get('method') == method]


def bridge_for(helper, db=None, **kwargs):
    kwargs.setdefault('request_timeout', 5.0)
    kwargs.setdefault('shutdown_timeout', 2.0)
    return MessagesBridge(helper, db, paired_chat_id=PAIRED, **kwargs)


async def collect(bridge, count, timeout=5.0):
    async def take():
        found = []
        async for event in bridge.messages():
            found.append(event)
            if len(found) == count:
                break
        return found
    return await asyncio.wait_for(take(), timeout)


# --- helper verification -------------------------------------------------

async def test_safe_helper_starts_initializes_and_verifies_chat(tmp_path):
    helper = make_helper(tmp_path)
    async with bridge_for(helper) as bridge:
        assert bridge is not None
    assert methods(tmp_path) == ['initialize', 'chats.get']


@pytest.mark.parametrize('mode_bits', [0o707, 0o720, 0o770, 0o600])
async def test_rejects_unsafe_mode_before_spawn(tmp_path, mode_bits):
    helper = make_helper(tmp_path, mode_bits=mode_bits)
    with patch('broker.imessage_bridge.asyncio.create_subprocess_exec', side_effect=AssertionError('spawned')) as spawn:
        with pytest.raises(MessagesBridgeError) as error:
            await bridge_for(helper).start()
    assert error.value.code == 'unsafe_helper'
    assert not spawn.called


async def test_rejects_symlinked_helper(tmp_path):
    real = make_helper(tmp_path, name='real')
    link = tmp_path / 'link'
    link.symlink_to(real)
    with patch('broker.imessage_bridge.asyncio.create_subprocess_exec', side_effect=AssertionError('spawned')):
        with pytest.raises(MessagesBridgeError) as error:
            await bridge_for(link).start()
    assert error.value.code == 'unsafe_helper'


async def test_rejects_missing_and_directory_helper(tmp_path):
    (tmp_path / 'adir').mkdir()
    for path in [tmp_path / 'missing', tmp_path / 'adir']:
        with pytest.raises(MessagesBridgeError) as error:
            await bridge_for(path).start()
        assert error.value.code == 'unsafe_helper'


async def test_rejects_group_writable_parent_directory(tmp_path):
    shared = tmp_path / 'shared'
    shared.mkdir(mode=0o700)
    helper = make_helper(tmp_path, name='imsg-in-shared', directory=shared)
    shared.chmod(0o770)
    with patch('broker.imessage_bridge.asyncio.create_subprocess_exec', side_effect=AssertionError('spawned')):
        with pytest.raises(MessagesBridgeError) as error:
            await bridge_for(helper).start()
    assert error.value.code == 'unsafe_helper'


async def test_rejects_world_writable_parent_directory(tmp_path):
    shared = tmp_path / 'open'
    shared.mkdir(mode=0o700)
    helper = make_helper(tmp_path, name='imsg-in-open', directory=shared)
    shared.chmod(0o777)
    with patch('broker.imessage_bridge.asyncio.create_subprocess_exec', side_effect=AssertionError('spawned')):
        with pytest.raises(MessagesBridgeError) as error:
            await bridge_for(helper).start()
    assert error.value.code == 'unsafe_helper'


async def test_rejects_parent_not_owned_by_user_or_root(tmp_path):
    helper = make_helper(tmp_path, name='imsg-foreign-parent')
    foreign = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=os.getuid() + 1000)
    real_info = os.stat

    def fake_directory_info(path):
        return foreign if Path(path) == tmp_path else real_info(path)

    with patch('broker.imessage_bridge._directory_info', side_effect=fake_directory_info):
        with patch('broker.imessage_bridge.asyncio.create_subprocess_exec', side_effect=AssertionError('spawned')):
            with pytest.raises(MessagesBridgeError) as error:
                await bridge_for(helper).start()
    assert error.value.code == 'unsafe_helper'


async def test_parents_above_home_are_not_inspected(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    bin_dir = home / 'bin'
    bin_dir.mkdir(mode=0o700)
    monkeypatch.setenv('HOME', str(home))
    helper = make_helper(tmp_path, name='imsg-home', directory=bin_dir)
    tmp_path.chmod(0o777)  # above home: the walk must stop at home
    try:
        async with bridge_for(helper):
            pass
    finally:
        tmp_path.chmod(0o700)
    assert methods(tmp_path) == ['initialize', 'chats.get']


async def test_writable_directory_between_helper_and_home_is_rejected(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    home.mkdir(mode=0o700)
    middle = home / 'middle'
    middle.mkdir(mode=0o700)
    monkeypatch.setenv('HOME', str(home))
    helper = make_helper(tmp_path, name='imsg-middle', directory=middle)
    middle.chmod(0o707)
    with patch('broker.imessage_bridge.asyncio.create_subprocess_exec', side_effect=AssertionError('spawned')):
        with pytest.raises(MessagesBridgeError) as error:
            await bridge_for(helper).start()
    assert error.value.code == 'unsafe_helper'


# --- argv / env / paths ----------------------------------------------------

async def test_argv_is_exact_and_carries_no_content(tmp_path, monkeypatch):
    monkeypatch.setenv('AGENTGATE_TEST_LEAK', 'parent-env-leak')
    helper = make_helper(tmp_path)
    db = tmp_path / 'chat.db'
    async with bridge_for(helper, db):
        pass
    start = requests(tmp_path)[0]
    assert start['argv'][1:] == ['rpc', '--db', str(db)]
    assert start['argv'][0] == str(helper)
    flat = json.dumps(start['argv'])
    assert str(PAIRED) not in flat and TEXT not in flat and GUID not in flat
    assert 'parent-env-leak' not in json.dumps(start['env'])
    assert start['env']['PATH'] and str(PAIRED) not in json.dumps(start['env'])


def test_minimal_env_contents(tmp_path, monkeypatch):
    from broker.helper_env import minimal_helper_env
    monkeypatch.setenv('HOME', str(tmp_path))
    assert set(minimal_helper_env()) == {'PATH', 'HOME'}


def test_default_db_path_is_absolute_under_home(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    bridge = bridge_for(tmp_path / 'imsg')
    assert bridge.db_path == tmp_path / 'Library' / 'Messages' / 'chat.db'
    assert bridge.db_path.is_absolute()


def test_relative_db_path_is_made_absolute(tmp_path):
    bridge = bridge_for(tmp_path / 'imsg', 'relative/chat.db')
    assert bridge.db_path.is_absolute()


def test_paired_chat_id_must_be_positive_int(tmp_path):
    for bad in [None, '42', True, 0, -1, 1.5]:
        with pytest.raises(MessagesBridgeError) as error:
            MessagesBridge(tmp_path / 'imsg', paired_chat_id=bad)
        assert error.value.code == 'invalid_input'


def test_database_identity_uses_stat_not_contents(tmp_path):
    db = tmp_path / 'chat.db'
    db.write_bytes(b'SECRET MESSAGE BODY')
    identity = bridge_for(tmp_path / 'imsg', db).database_identity()
    info = os.stat(db)
    assert identity == f'{info.st_dev}:{info.st_ino}'
    assert 'SECRET' not in identity


def test_database_identity_missing_is_unavailable(tmp_path):
    with pytest.raises(MessagesBridgeError) as error:
        bridge_for(tmp_path / 'imsg', tmp_path / 'absent.db').database_identity()
    assert error.value.code == 'database_unavailable'


# --- paired chat verification ----------------------------------------------

def _chat(**overrides):
    value = {'id': PAIRED, 'guid': GUID, 'service': 'iMessage', 'is_group': False,
             'participants': ['+15550100'], 'account_login': 'P:+15550100'}
    value.update(overrides)
    return value


def test_is_self_chat_accepts_only_one_to_one_chat_with_own_handle():
    assert is_self_chat(_chat())
    assert is_self_chat(_chat(account_login='E:Me@iCloud.com', participants=['me@icloud.com']))
    assert not is_self_chat(_chat(is_group=True))
    assert not is_self_chat(_chat(service='SMS'))
    assert not is_self_chat(_chat(guid='iMessage;+;chat1'))
    assert not is_self_chat(_chat(participants=['+15550100', '+15550199']))
    assert not is_self_chat(_chat(participants=[]))
    assert not is_self_chat(_chat(participants=['+15550199']))
    assert not is_self_chat(_chat(account_login=None))
    assert not is_self_chat(_chat(account_login=''))


def test_is_self_chat_accepts_any_service_guid_and_last_addressed_handle():
    # Observed on macOS 27: 1:1 GUIDs use 'any;-;', account_login is the Apple ID
    # email, and the self-chat participant equals the handle you send from.
    real = dict(guid='any;-;+15550100', account_login='me@icloud.com',
                last_addressed_handle='+15550100')
    assert is_self_chat(_chat(**real))
    # A chat with someone else: you address it from your handle, they are the participant.
    assert not is_self_chat(_chat(**{**real, 'participants': ['+15550199']}))
    assert not is_self_chat(_chat(**{**real, 'guid': 'any;+;chat123'}))
    assert not is_self_chat(_chat(**{**real, 'service': 'SMS'}))
    assert not is_self_chat(_chat(**{**real, 'last_addressed_handle': None}))
    assert not is_self_chat(_chat(**{**real, 'last_addressed_handle': ''}))


@pytest.mark.parametrize('mode', ['chat_group', 'chat_sms', 'chat_two', 'chat_other_account'])
async def test_start_refuses_unverified_paired_chat(tmp_path, mode):
    helper = make_helper(tmp_path, mode=mode)
    with pytest.raises(MessagesBridgeError) as error:
        await bridge_for(helper).start()
    assert error.value.code == 'chat_mismatch'
    assert 'send' not in methods(tmp_path)


async def test_send_uses_cached_verified_guid_only(tmp_path):
    helper = make_helper(tmp_path)
    async with bridge_for(helper) as bridge:
        assert await bridge.send_text('Reply text') is True
    assert params_of(tmp_path, 'send') == [{'chat_guid': GUID, 'text': 'Reply text', 'service': 'imessage',
                                            'transport': 'applescript', 'allow_sms_fallback': False}]


def test_send_text_accepts_no_chat_identifiers():
    assert list(inspect.signature(MessagesBridge.send_text).parameters) == ['self', 'text']


async def test_send_before_start_refused_without_writing(tmp_path):
    helper = make_helper(tmp_path)
    bridge = bridge_for(helper)
    with pytest.raises(MessagesBridgeError) as error:
        await bridge.send_text(TEXT)
    assert error.value.code == 'not_running'
    assert not requests(tmp_path)


@pytest.mark.parametrize('text', ['', 'x' * 4001, 'bad\x00text', 42])
async def test_send_invalid_text_refused_without_writing(tmp_path, text):
    helper = make_helper(tmp_path)
    async with bridge_for(helper) as bridge:
        with pytest.raises(MessagesBridgeError) as error:
            await bridge.send_text(text)
        assert error.value.code == 'invalid_input'
    assert 'send' not in methods(tmp_path)


# --- allowlist and pairing -------------------------------------------------

@pytest.mark.parametrize('method', ['launch', 'typing', 'contacts.list', 'chats.list',
                                    'messages.history', 'attachments.get', 'mark_read', 'SEND', ''])
async def test_disallowed_method_is_never_written(tmp_path, method):
    helper = make_helper(tmp_path)
    async with bridge_for(helper) as bridge:
        with pytest.raises(MessagesBridgeError) as error:
            await bridge._request(method, {})
        assert error.value.code == 'method_not_allowed'
    assert method not in methods(tmp_path)


async def test_get_chat_refuses_other_chats(tmp_path):
    helper = make_helper(tmp_path)
    async with bridge_for(helper) as bridge:
        with pytest.raises(MessagesBridgeError) as error:
            await bridge.get_chat(PAIRED + 1)
        assert error.value.code == 'chat_not_paired'
    assert methods(tmp_path).count('chats.get') == 1  # only the start-up verification


async def test_subscribe_uses_paired_chat_only(tmp_path):
    helper = make_helper(tmp_path)
    async with bridge_for(helper) as bridge:
        assert await bridge.subscribe(0) == 7
    by_method = {entry['method']: entry for entry in requests(tmp_path) if 'method' in entry}
    assert by_method['chats.get']['params'] == {'chat_id': PAIRED}
    assert by_method['initialize']['params'] == {'protocol_version': 1}
    assert by_method['watch.subscribe']['params'] == {
        'chat_id': PAIRED, 'since_rowid': 0, 'attachments': False,
        'include_reactions': False, 'debounce_ms': 500, 'buffer_limit': 64}


async def test_pairing_bridge_lists_candidates_and_history(tmp_path):
    helper = make_helper(tmp_path)
    async with PairingBridge(helper, request_timeout=5.0, shutdown_timeout=2.0) as bridge:
        assert await bridge.list_chats(limit=25) == [PAIRED]
        history = await bridge.history(PAIRED, limit=10)
        chat = await bridge.get_chat(PAIRED)
    assert params_of(tmp_path, 'chats.list') == [{'limit': 25}]
    assert params_of(tmp_path, 'messages.history') == [{'chat_id': PAIRED, 'limit': 10}]
    assert [m['rowid'] for m in history] == [201, 202]
    assert history[0]['is_from_me'] is True and history[0]['text'] == '/agent pair AG-TEST23'
    assert history[1]['text'] == ''
    assert chat['guid'] == GUID and chat['account_login'] == 'P:+15550100'
    assert chat['last_addressed_handle'] is None


async def test_pairing_bridge_cannot_send_or_subscribe(tmp_path):
    helper = make_helper(tmp_path)
    async with PairingBridge(helper, request_timeout=5.0, shutdown_timeout=2.0) as bridge:
        with pytest.raises(MessagesBridgeError) as error:
            await bridge.send_text(TEXT)
        assert error.value.code == 'not_running'
        with pytest.raises(MessagesBridgeError) as error:
            await bridge.subscribe(0)
        assert error.value.code == 'method_not_allowed'
    assert 'send' not in methods(tmp_path) and 'watch.subscribe' not in methods(tmp_path)


async def test_pairing_bridge_does_not_require_a_paired_chat(tmp_path):
    helper = make_helper(tmp_path)
    async with PairingBridge(helper, request_timeout=5.0, shutdown_timeout=2.0) as bridge:
        # The fake answers with the paired chat's metadata; a mismatched id must not be trusted.
        with pytest.raises(MessagesBridgeError) as error:
            await bridge.get_chat(PAIRED + 7)
        assert error.value.code == 'protocol_error'
    assert params_of(tmp_path, 'chats.get')[-1] == {'chat_id': PAIRED + 7}


@pytest.mark.parametrize('call', [
    lambda b: b.list_chats(limit=0),
    lambda b: b.list_chats(limit=51),
    lambda b: b.history(-1, limit=10),
    lambda b: b.history(PAIRED, limit=True),
    lambda b: b.history(PAIRED, limit=51),
])
async def test_pairing_bridge_limits_are_enforced(tmp_path, call):
    helper = make_helper(tmp_path)
    async with PairingBridge(helper, request_timeout=5.0, shutdown_timeout=2.0) as bridge:
        with pytest.raises(MessagesBridgeError) as error:
            await call(bridge)
        assert error.value.code in ('invalid_input', 'chat_not_paired')
    assert not {'chats.list', 'messages.history'} & set(methods(tmp_path))


# --- request/response matching and bounds ----------------------------------

async def test_request_ids_are_unique_and_responses_matched(tmp_path):
    helper = make_helper(tmp_path, mode='stray')
    async with bridge_for(helper) as bridge:
        assert (await bridge.get_chat(PAIRED))['guid'] == GUID
        assert (await bridge.get_chat(PAIRED))['guid'] == GUID
    ids = [e['id'] for e in requests(tmp_path) if 'id' in e]
    assert len(ids) == len(set(ids)) == 4


async def test_request_timeout_is_generic(tmp_path):
    helper = make_helper(tmp_path, mode='hang')
    async with bridge_for(helper, request_timeout=0.3) as bridge:
        with pytest.raises(MessagesBridgeError) as error:
            await bridge.get_chat(PAIRED)
    assert error.value.code == 'timeout'


async def test_send_timeout_is_uncertain_and_not_retried(tmp_path):
    helper = make_helper(tmp_path, mode='hang')
    async with bridge_for(helper, send_timeout=0.3) as bridge:
        with pytest.raises(MessagesBridgeError) as error:
            await bridge.send_text(TEXT)
    assert error.value.code == 'send_uncertain'
    assert methods(tmp_path).count('send') == 1


async def test_send_uses_longer_timeout_than_other_requests(tmp_path):
    helper = make_helper(tmp_path, mode='slow_send')
    async with bridge_for(helper, request_timeout=0.2) as bridge:
        assert await bridge.send_text(TEXT) is True
    assert methods(tmp_path).count('send') == 1


async def test_send_32004_is_blocked_and_not_retried(tmp_path):
    async with bridge_for(make_helper(tmp_path, mode='send_32004')) as bridge:
        with pytest.raises(MessagesBridgeError) as error:
            await bridge.send_text(TEXT)
    assert error.value.code == 'send_blocked'
    assert methods(tmp_path).count('send') == 1


async def test_send_32001_is_uncertain_other_rpc_errors_are_failed(tmp_path):
    async with bridge_for(make_helper(tmp_path, mode='send_32001', name='a')) as bridge:
        with pytest.raises(MessagesBridgeError) as error:
            await bridge.send_text(TEXT)
    assert error.value.code == 'send_uncertain'
    async with bridge_for(make_helper(tmp_path, mode='send_error', name='b')) as bridge:
        with pytest.raises(MessagesBridgeError) as error:
            await bridge.send_text(TEXT)
    assert error.value.code == 'send_failed'


async def test_rpc_error_is_generic_and_leaks_nothing(tmp_path):
    helper = make_helper(tmp_path, mode='error_rpc')
    async with bridge_for(helper) as bridge:
        with pytest.raises(MessagesBridgeError) as error:
            await bridge.get_chat(PAIRED)
    assert error.value.code == 'rpc_error'
    assert 'leak' not in str(error.value) and 'SECRET' not in str(error.value)


async def test_oversized_response_line_is_dropped_and_bridge_recovers(tmp_path):
    helper = make_helper(tmp_path, mode='oversize')
    async with bridge_for(helper, request_timeout=0.5) as bridge:
        with pytest.raises(MessagesBridgeError) as error:
            await bridge.get_chat(PAIRED)
        assert error.value.code == 'timeout'
        assert (await bridge.get_chat(PAIRED))['guid'] == GUID


async def test_child_exit_fails_start_with_bridge_closed(tmp_path):
    helper = make_helper(tmp_path, mode='exit_after_init')
    with pytest.raises(MessagesBridgeError) as error:
        await bridge_for(helper).start()
    assert error.value.code == 'bridge_closed'


async def test_not_running_before_start(tmp_path):
    bridge = bridge_for(make_helper(tmp_path))
    with pytest.raises(MessagesBridgeError) as error:
        await bridge.get_chat(PAIRED)
    assert error.value.code == 'not_running'
    with pytest.raises(MessagesBridgeError) as error:
        await collect(bridge, 1)
    assert error.value.code == 'not_running'


# --- notifications ---------------------------------------------------------

async def test_notifications_normalized_and_malformed_dropped(tmp_path):
    helper = make_helper(tmp_path, mode='normal')
    async with bridge_for(helper) as bridge:
        await bridge.subscribe(0)
        events = await collect(bridge, 2)
    first, second = events
    assert first['rowid'] == 103 and second['rowid'] == 104
    assert first['chat_id'] == PAIRED and second['chat_id'] == PAIRED
    assert first['date'].tzinfo is not None
    assert first['date'].isoformat() == '2026-10-12T12:00:00+00:00'
    assert len(first['text']) == 4000 and first['text'].startswith('hello aaa')
    assert first['is_from_me'] is False and second['is_from_me'] is True
    assert second['text'] == 'reply'
    assert set(first) == {'chat_id', 'chat_guid', 'guid', 'rowid', 'date', 'text',
                          'is_from_me', 'is_group', 'sender'}
    assert first['guid'] == 'G103' and first['chat_guid'] == GUID


async def test_notification_buffer_overflow_is_fail_closed(tmp_path):
    helper = make_helper(tmp_path, mode='burst')
    async with bridge_for(helper, max_events=3) as bridge:
        await bridge.subscribe(0)
        await asyncio.sleep(0.5)  # consumer is slow: the backlog exceeds max_events
        with pytest.raises(MessagesBridgeError) as error:
            await collect(bridge, 5)
    assert error.value.code == 'overflow'


async def test_watch_overflow_recovers_with_bounded_messages_after(tmp_path):
    helper = make_helper(tmp_path, mode='recover')
    async with bridge_for(helper) as bridge:
        await bridge.subscribe(0)
        events = await collect(bridge, 4)
    assert [e['rowid'] for e in events] == [101, 102, 103, 105]  # 106 (stale, post-overflow) dropped
    assert params_of(tmp_path, 'messages.after') == [{
        'chat_id': PAIRED, 'since_rowid': 102, 'limit': 100, 'attachments': False,
        'convert_attachments': False, 'include_reactions': False}]
    assert [p['since_rowid'] for p in params_of(tmp_path, 'watch.subscribe')] == [0, 104]


async def test_recovery_page_loop_is_bounded_then_fails_closed(tmp_path):
    helper = make_helper(tmp_path, mode='recover_pages')
    async with bridge_for(helper) as bridge:
        await bridge.subscribe(0)
        with pytest.raises(MessagesBridgeError) as error:
            await collect(bridge, 10)
    assert error.value.code == 'overflow'
    assert methods(tmp_path).count('messages.after') == 5


async def test_recovery_with_regressing_cursor_is_protocol_error(tmp_path):
    helper = make_helper(tmp_path, mode='recover_regress')
    async with bridge_for(helper) as bridge:
        await bridge.subscribe(0)
        with pytest.raises(MessagesBridgeError) as error:
            await collect(bridge, 10)
    assert error.value.code == 'protocol_error'


async def test_overflow_marker_with_full_queue_fails_closed(tmp_path):
    helper = make_helper(tmp_path, mode='overflow_full')
    async with bridge_for(helper, max_events=3) as bridge:
        await bridge.subscribe(0)
        await asyncio.sleep(0.5)  # queue is full with 3 events when the recovery marker arrives
        with pytest.raises(MessagesBridgeError) as error:
            await collect(bridge, 10)
    assert error.value.code == 'overflow'
    assert 'messages.after' not in methods(tmp_path)


async def test_watch_overflow_without_resume_cursor_fails_closed(tmp_path):
    helper = make_helper(tmp_path, mode='overflow_bad')
    async with bridge_for(helper) as bridge:
        await bridge.subscribe(0)
        with pytest.raises(MessagesBridgeError) as error:
            await collect(bridge, 10)
    assert error.value.code == 'overflow'
    assert 'messages.after' not in methods(tmp_path)


# --- shutdown --------------------------------------------------------------

async def test_close_kills_child_that_ignores_sigterm(tmp_path):
    helper = make_helper(tmp_path, mode='ignore_term')
    bridge = bridge_for(helper, shutdown_timeout=0.3)
    await bridge.start()
    process = bridge._proc
    await asyncio.wait_for(bridge.close(), 5)
    assert process.returncode is not None
    await bridge.close()  # idempotent


async def test_close_ends_iteration_cleanly(tmp_path):
    helper = make_helper(tmp_path, mode='normal')
    bridge = bridge_for(helper)
    await bridge.start()
    await bridge.subscribe(0)
    await asyncio.sleep(0.5)
    await bridge.close()
    events = [event['rowid'] async for event in bridge.messages()]
    assert events == [103, 104]


async def test_context_manager_closes_child(tmp_path):
    helper = make_helper(tmp_path)
    async with bridge_for(helper) as bridge:
        process = bridge._proc
    assert process.returncode is not None
    with pytest.raises(MessagesBridgeError) as error:
        await bridge.get_chat(PAIRED)
    assert error.value.code == 'not_running'


async def test_no_message_text_in_exception_text(tmp_path):
    helper = make_helper(tmp_path, mode='send_error')
    async with bridge_for(helper) as bridge:
        with pytest.raises(MessagesBridgeError) as error:
            await bridge.send_text(TEXT)
    assert TEXT not in str(error.value) and 'nope' not in str(error.value)
