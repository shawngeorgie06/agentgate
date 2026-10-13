import asyncio
import datetime as dt
import json
import os
import re
import stat
import threading

import pytest

from broker import imessage_service as svc
from broker.agent_registry import AgentRegistry
from broker.imessage_bridge import MessagesBridgeError
from broker.imessage_service import AsyncAppleModel, IMessageService, ModelError

T0 = dt.datetime(2026, 10, 12, 12, 0, tzinfo=dt.timezone.utc)
SELF_CHAT = 424242
GROUP_CHAT = 424300
OTHER_CHAT = 424243
HANDLE = '+15550100'
GUID = 'iMessage;-;+15550100'
CODE_PATTERN = re.compile(r'AG-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{6}')


class Clock:
    def __init__(self):
        self.now = T0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += dt.timedelta(seconds=seconds)


class FakeModel:
    def __init__(self, available=True):
        self.prompts = []
        self.threads = []
        self._available = available

    async def plan(self, prompt, history=''):
        self.prompts.append(prompt)
        return {'action': 'chat', 'query': '', 'message_id': '', 'owner': '', 'repo': '', 'path': '', 'ref': ''}

    async def answer(self, prompt, context, history=''):
        return 'Summary'

    def availability(self):
        self.threads.append(threading.get_ident())
        if self._available:
            return {'available': True, 'reason': 'Available on this Mac.'}
        return {'available': False, 'reason': 'Apple Intelligence is not enabled.'}


class FakeTools:
    def __init__(self):
        self.calls = []

    async def execute(self, agent, resource, operation, *, identity_guard, **args):
        self.calls.append((agent, resource, operation))
        return {'ok': False, 'reason': 'not used'}


class FakeWorld:
    """Shared state for every FakeBridge a service opens during one test."""

    def __init__(self):
        self.chats = {SELF_CHAT: self_chat()}
        self.history = {}
        self.database = 'db-1'
        self.queue = asyncio.Queue()
        self.sent = []
        self.send_attempts = 0
        self.send_error = None
        self.on_send = None
        self.history_calls = []
        self.opened = []
        self.subscriptions = []
        self.crash_messages = 0

    def bridge(self, chat_id):
        self.opened.append(chat_id)
        return FakeBridge(self, chat_id)


class FakeBridge:
    def __init__(self, world, chat_id):
        self.world = world
        self.chat_id = chat_id
        self.closed = False

    async def start(self):
        return None

    async def close(self):
        self.closed = True

    def database_identity(self):
        return self.world.database

    async def list_chats(self, limit=25):
        return list(self.world.chats)[:limit]

    async def get_chat(self, chat_id):
        if chat_id not in self.world.chats:
            raise MessagesBridgeError('rpc_error')
        return self.world.chats[chat_id]

    async def history(self, chat_id, limit=10):
        self.world.history_calls.append(chat_id)
        return list(self.world.history.get(chat_id, []))

    async def subscribe(self, since_rowid=0):
        self.world.subscriptions.append(since_rowid)
        return 1

    async def messages(self):
        if self.world.crash_messages > 0:
            self.world.crash_messages -= 1
            raise MessagesBridgeError('bridge_closed')
        while True:
            yield await self.world.queue.get()

    async def send_text(self, text):
        self.world.send_attempts += 1
        if self.world.send_error is not None:
            raise self.world.send_error
        self.world.sent.append((self.chat_id, text))
        if self.world.on_send is not None:
            self.world.on_send()
        return True


def self_chat(chat_id=SELF_CHAT, **overrides):
    value = {'id': chat_id, 'guid': GUID, 'service': 'iMessage', 'is_group': False,
             'participants': [HANDLE], 'account_login': 'P:' + HANDLE}
    value.update(overrides)
    return value


def history_row(rowid, text, *, chat_id=SELF_CHAT, from_me=True, date=None):
    return {'rowid': rowid, 'chat_id': chat_id, 'text': text, 'is_from_me': from_me,
            'date': date or T0 + dt.timedelta(seconds=1)}


def event(clock, rowid, text, *, chat_id=SELF_CHAT, from_me=True, is_group=False, guid=None):
    return {'chat_id': chat_id, 'chat_guid': GUID, 'guid': guid or f'G{rowid}', 'rowid': rowid,
            'date': clock.now + dt.timedelta(seconds=1), 'text': text, 'is_from_me': from_me,
            'is_group': is_group, 'sender': ''}


def make_service(tmp_path, world, clock, *, registry=None, helpers=True, model=None):
    registry = registry or AgentRegistry(tmp_path / 'agents.sqlite3')
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir(exist_ok=True)
    imsg = bin_dir / 'imsg'
    model_helper = bin_dir / 'agentgate-model'
    if helpers:
        for path in (imsg, model_helper):
            path.write_text('#!/bin/sh\n')
            path.chmod(0o700)
    return IMessageService(tmp_path / 'config', registry, FakeTools(), FakeTools(),
                           imsg_path=imsg, model_helper_path=model_helper,
                           bridge_factory=world.bridge, model=model or FakeModel(), clock=clock)


def settings_path(tmp_path):
    return tmp_path / 'config' / 'imessage.json'


async def wait_until(predicate, timeout=3.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not predicate():
        if loop.time() > deadline:
            raise AssertionError('condition was not reached in time')
        await asyncio.sleep(0.01)


async def pair(service, world, agent_id='helper'):
    status = await service.start_pairing(agent_id)
    code = status['pairing']['code']
    world.history[SELF_CHAT] = [history_row(501, f'/agent pair {code}')]
    await wait_until(lambda: service.status()['paired'])
    return code


@pytest.fixture(autouse=True)
def fast_timers(monkeypatch):
    monkeypatch.setattr(svc, 'PAIRING_POLL_SECONDS', 0.01)
    monkeypatch.setattr(svc, 'RETRY_BASE_SECONDS', 0.01)


@pytest.fixture
def registry(tmp_path):
    reg = AgentRegistry(tmp_path / 'agents.sqlite3')
    reg.register('helper')
    return reg


# --- status and availability ----------------------------------------------

async def test_status_without_helpers_reports_unavailable_and_nothing_else(tmp_path, registry):
    service = make_service(tmp_path, FakeWorld(), Clock(), registry=registry, helpers=False)
    status = await service.snapshot()
    assert status == {
        'available': False, 'enabled': False, 'paired': False, 'running': False, 'agent': None,
        'model': {'available': True, 'reason': 'Available on this Mac.'},
        'pairing': None, 'recent': [], 'error': None,
    }


async def test_status_reports_model_unavailable_reason(tmp_path, registry):
    service = make_service(tmp_path, FakeWorld(), Clock(), registry=registry,
                           model=FakeModel(available=False))
    assert (await service.snapshot())['model'] == {'available': False, 'reason': 'Apple Intelligence is not enabled.'}


async def test_model_check_is_cached_for_a_minute_and_runs_off_the_loop(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    model = FakeModel()
    service = make_service(tmp_path, world, clock, registry=registry, model=model)
    assert service.status()['model']['available'] is False  # Not checked yet; sync status never blocks.
    assert model.threads == []
    await service.snapshot()
    await service.snapshot()
    service.status()
    assert len(model.threads) == 1
    assert model.threads[0] != threading.get_ident()
    clock.advance(59)
    await service.snapshot()
    assert len(model.threads) == 1
    clock.advance(2)
    await service.snapshot()
    assert len(model.threads) == 2


async def test_async_mutations_check_the_model_off_the_loop(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    model = FakeModel()
    service = make_service(tmp_path, world, clock, registry=registry, model=model)
    await pair(service, world)
    await service.enable()
    await service.disable()
    assert model.threads
    assert threading.get_ident() not in model.threads
    await service.stop()


async def test_start_pairing_refuses_unknown_revoked_or_invalid_agents(tmp_path, registry):
    clock = Clock()
    service = make_service(tmp_path, FakeWorld(), clock, registry=registry)
    with pytest.raises(ValueError):
        await service.start_pairing('nobody')
    with pytest.raises(ValueError):
        await service.start_pairing(None)
    registry.revoke('helper')
    with pytest.raises(ValueError):
        await service.start_pairing('helper')
    assert service.status()['pairing'] is None


async def test_start_pairing_issues_code_valid_for_ten_minutes(tmp_path, registry):
    clock = Clock()
    service = make_service(tmp_path, FakeWorld(), clock, registry=registry)
    status = await service.start_pairing('helper')
    assert CODE_PATTERN.fullmatch(status['pairing']['code'])
    assert dt.datetime.fromisoformat(status['pairing']['expires_at']) == T0 + dt.timedelta(minutes=10)
    assert status['enabled'] is False and status['paired'] is False
    await service.stop()


async def test_start_pairing_without_helpers_reports_error_and_issues_no_code(tmp_path, registry):
    service = make_service(tmp_path, FakeWorld(), Clock(), registry=registry, helpers=False)
    status = await service.start_pairing('helper')
    assert status['pairing'] is None
    assert status['error'] == svc.ERR_UNAVAILABLE


async def test_status_never_exposes_chat_ids_handles_guids_or_text(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)
    await pair(service, world)
    await service.enable()
    world.queue.put_nowait(event(clock, 900, '/agent check hello there'))
    await wait_until(lambda: len(world.sent) == 2)
    text = json.dumps(service.status())
    for secret in (str(SELF_CHAT), HANDLE, GUID, 'hello there', 'check'):
        assert secret not in text
    await service.stop()


# --- pairing ---------------------------------------------------------------

async def test_pairing_accepts_exact_code_in_one_to_one_self_chat(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)
    await pair(service, world)
    status = service.status()
    assert status['paired'] is True and status['enabled'] is False and status['pairing'] is None
    assert status['agent'] == {'id': 'helper', 'name': 'helper'}
    assert json.loads(settings_path(tmp_path).read_text()) == {
        'enabled': False, 'paired': {'chat_id': SELF_CHAT, 'agent_id': 'helper'}}
    assert stat.S_IMODE(os.stat(settings_path(tmp_path)).st_mode) == 0o600
    assert world.sent == [(SELF_CHAT, 'AgentGate paired.')]
    await service.stop()


async def test_pairing_accepts_self_chat_identified_by_last_addressed_handle(tmp_path, registry):
    # macOS 27 shape: 'any;-;' GUID, email login, phone self-chat.
    world, clock = FakeWorld(), Clock()
    world.chats[SELF_CHAT] = self_chat(guid='any;-;' + HANDLE, account_login='me@icloud.com',
                                       last_addressed_handle=HANDLE)
    service = make_service(tmp_path, world, clock, registry=registry)
    await pair(service, world)
    assert service.status()['paired'] is True
    assert world.sent == [(SELF_CHAT, 'AgentGate paired.')]
    await service.stop()


@pytest.mark.parametrize('case', ['group', 'other_participant', 'sms', 'not_from_me', 'extra_text', 'wrong_case', 'other_code'])
async def test_pairing_ignores_everything_but_the_exact_code_in_a_self_chat(tmp_path, registry, case):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)
    code = (await service.start_pairing('helper'))['pairing']['code']
    if case == 'group':
        world.chats[GROUP_CHAT] = self_chat(GROUP_CHAT, is_group=True, guid='iMessage;+;chat1')
        world.history[GROUP_CHAT] = [history_row(501, f'/agent pair {code}', chat_id=GROUP_CHAT)]
    elif case == 'other_participant':
        world.chats[OTHER_CHAT] = self_chat(OTHER_CHAT, participants=['+15559999'])
        world.history[OTHER_CHAT] = [history_row(501, f'/agent pair {code}', chat_id=OTHER_CHAT)]
    elif case == 'sms':
        world.chats[OTHER_CHAT] = self_chat(OTHER_CHAT, service='SMS')
        world.history[OTHER_CHAT] = [history_row(501, f'/agent pair {code}', chat_id=OTHER_CHAT)]
    elif case == 'not_from_me':
        world.history[SELF_CHAT] = [history_row(501, f'/agent pair {code}', from_me=False)]
    elif case == 'extra_text':
        world.history[SELF_CHAT] = [history_row(501, f'/agent pair {code} please')]
    elif case == 'wrong_case':
        world.history[SELF_CHAT] = [history_row(501, f'/agent pair {code.lower()}')]
    elif case == 'other_code':
        world.history[SELF_CHAT] = [history_row(501, '/agent pair AG-ZZZZZZ')]
    await asyncio.sleep(0.1)
    status = service.status()
    assert status['paired'] is False
    assert status['pairing'] is not None
    assert GROUP_CHAT not in world.history_calls
    assert OTHER_CHAT not in world.history_calls
    await service.stop()


async def test_pairing_never_reads_history_of_non_self_chats(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    world.chats[GROUP_CHAT] = self_chat(GROUP_CHAT, is_group=True)
    world.chats[OTHER_CHAT] = self_chat(OTHER_CHAT, participants=['+15559999'])
    service = make_service(tmp_path, world, clock, registry=registry)
    await service.start_pairing('helper')
    await asyncio.sleep(0.1)
    assert GROUP_CHAT not in world.history_calls
    assert OTHER_CHAT not in world.history_calls
    await service.stop()


async def test_pairing_code_expires_after_ten_minutes(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)
    code = (await service.start_pairing('helper'))['pairing']['code']
    clock.advance(601)
    await wait_until(lambda: service.status()['pairing'] is None)
    assert service.status()['error'] == svc.ERR_EXPIRED
    world.history[SELF_CHAT] = [history_row(501, f'/agent pair {code}')]
    await asyncio.sleep(0.05)
    assert service.status()['paired'] is False
    await service.stop()


async def test_cancel_pairing_stops_polling(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)
    code = (await service.start_pairing('helper'))['pairing']['code']
    status = await service.cancel_pairing()
    assert status['pairing'] is None
    world.history[SELF_CHAT] = [history_row(501, f'/agent pair {code}')]
    await asyncio.sleep(0.05)
    assert service.status()['paired'] is False
    await service.stop()


async def test_restarting_pairing_invalidates_the_previous_code(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)
    first = (await service.start_pairing('helper'))['pairing']['code']
    second = (await service.start_pairing('helper'))['pairing']['code']
    assert first != second
    world.history[SELF_CHAT] = [history_row(501, f'/agent pair {first}')]
    await asyncio.sleep(0.05)
    assert service.status()['paired'] is False
    world.history[SELF_CHAT] = [history_row(502, f'/agent pair {second}')]
    await wait_until(lambda: service.status()['paired'])
    await service.stop()


async def test_repairing_disables_an_enabled_agent_until_explicitly_enabled(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)
    await pair(service, world)
    await service.enable()
    assert service.status()['running'] is True
    await service.start_pairing('helper')
    status = service.status()
    assert status['enabled'] is False and status['running'] is False
    await service.stop()


# --- enablement and persistence --------------------------------------------

async def test_enable_requires_pairing(tmp_path, registry):
    service = make_service(tmp_path, FakeWorld(), Clock(), registry=registry)
    status = await service.enable()
    assert status['enabled'] is False and status['error'] == svc.ERR_NOT_PAIRED


async def test_enable_refused_when_model_unavailable(tmp_path, registry):
    world = FakeWorld()
    service = make_service(tmp_path, world, Clock(), registry=registry, model=FakeModel(available=False))
    await pair(service, world)
    status = await service.enable()
    assert status['enabled'] is False and status['running'] is False
    assert status['error'] == svc.ERR_MODEL
    await service.stop()


async def test_enable_disable_unpair_persist_and_restart_respects_enabled_flag(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)
    await pair(service, world)
    assert (await service.enable())['enabled'] is True
    assert json.loads(settings_path(tmp_path).read_text())['enabled'] is True
    assert (await service.disable())['running'] is False
    assert json.loads(settings_path(tmp_path).read_text())['enabled'] is False

    await service.enable()
    restarted = make_service(tmp_path, world, clock, registry=registry)
    await restarted.start()
    assert restarted.status()['running'] is True
    await restarted.stop()
    assert restarted.status()['running'] is False

    unpaired = await service.unpair()
    assert unpaired['paired'] is False and unpaired['enabled'] is False and unpaired['agent'] is None
    assert json.loads(settings_path(tmp_path).read_text()) == {'enabled': False, 'paired': None}
    await service.stop()


async def test_start_does_not_run_loop_when_disabled(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)
    await pair(service, world)
    await service.start()
    assert service.status()['running'] is False
    await service.stop()


async def test_unreadable_settings_fail_closed(tmp_path, registry):
    config = tmp_path / 'config'
    config.mkdir()
    settings_path(tmp_path).write_text('{"enabled": true, "paired": {"chat_id": 1, "agent_id": "helper"}}')
    settings_path(tmp_path).chmod(0o644)
    service = make_service(tmp_path, FakeWorld(), Clock(), registry=registry)
    status = service.status()
    assert status['paired'] is False and status['enabled'] is False
    assert status['error'] == svc.ERR_UNREADABLE


async def test_settings_symlink_is_refused(tmp_path, registry):
    config = tmp_path / 'config'
    config.mkdir()
    target = tmp_path / 'elsewhere.json'
    target.write_text('{"enabled": true, "paired": {"chat_id": 1, "agent_id": "helper"}}')
    target.chmod(0o600)
    os.symlink(target, settings_path(tmp_path))
    service = make_service(tmp_path, FakeWorld(), Clock(), registry=registry)
    assert service.status()['paired'] is False
    assert service.status()['error'] == svc.ERR_UNREADABLE


async def test_corrupt_settings_fail_closed(tmp_path, registry):
    (tmp_path / 'config').mkdir()
    settings_path(tmp_path).write_text('not json')
    settings_path(tmp_path).chmod(0o600)
    service = make_service(tmp_path, FakeWorld(), Clock(), registry=registry)
    assert service.status()['paired'] is False
    assert service.status()['error'] == svc.ERR_UNREADABLE


# --- command loop ----------------------------------------------------------

async def test_command_is_answered_once_in_paired_chat_and_marked_before_send(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    model = FakeModel()
    service = make_service(tmp_path, world, clock, registry=registry, model=model)
    await pair(service, world)
    observed = []
    world.on_send = lambda: observed.append(service.status()['recent'][0]['status'])
    await service.enable()
    world.queue.put_nowait(event(clock, 900, '/agent hello there', guid='cmd-1'))
    world.queue.put_nowait(event(clock, 900, '/agent hello there', guid='cmd-1'))
    await wait_until(lambda: len(world.sent) == 2)
    await asyncio.sleep(0.05)
    assert world.sent[-1] == (SELF_CHAT, 'Summary')
    assert len(world.sent) == 2
    assert model.prompts == ['hello there']
    assert observed == ['attempted']
    assert service.status()['recent'][0]['status'] == 'sent'
    await service.stop()


async def test_ignored_events_never_reach_the_agent(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    model = FakeModel()
    service = make_service(tmp_path, world, clock, registry=registry, model=model)
    await pair(service, world)
    await service.enable()
    world.queue.put_nowait(event(clock, 901, '/agent sneaky', from_me=False))
    world.queue.put_nowait(event(clock, 902, 'hello without marker'))
    world.queue.put_nowait(event(clock, 903, '/agentx nope'))
    world.queue.put_nowait(event(clock, 904, '/agent group', is_group=True))
    world.queue.put_nowait(event(clock, 905, '/agent elsewhere', chat_id=OTHER_CHAT))
    world.queue.put_nowait(event(clock, 906, '/agent   '))
    world.queue.put_nowait(event(clock, 907, '/agent real request', guid='real'))
    await wait_until(lambda: len(world.sent) == 2)
    assert model.prompts == ['real request']
    await service.stop()


async def test_uncertain_send_is_marked_failed_and_never_resent(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)
    await pair(service, world)
    await service.enable()
    world.send_error = MessagesBridgeError('send_uncertain')
    world.send_attempts = 0  # Count only the command's send, not the pairing confirmation.
    world.queue.put_nowait(event(clock, 900, '/agent check', guid='cmd-1'))
    await wait_until(lambda: service.status()['recent'][:1] and service.status()['recent'][0]['status'] == 'failed')
    await asyncio.sleep(0.05)
    assert world.send_attempts == 1
    assert [text for _chat, text in world.sent] == ['AgentGate paired.']
    await service.stop()


async def test_failed_send_is_marked_failed(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)
    await pair(service, world)
    await service.enable()
    world.send_error = MessagesBridgeError('send_failed')
    world.send_attempts = 0  # Count only the command's send, not the pairing confirmation.
    world.queue.put_nowait(event(clock, 900, '/agent check', guid='cmd-1'))
    await wait_until(lambda: service.status()['recent'][:1] and service.status()['recent'][0]['status'] == 'failed')
    assert world.send_attempts == 1
    await service.stop()


async def test_rate_limit_drops_excess_with_at_most_one_notice(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)
    await pair(service, world)
    await service.enable()

    world.queue.put_nowait(event(clock, 900, '/agent one', guid='c1'))
    await wait_until(lambda: len(world.sent) == 2)
    world.queue.put_nowait(event(clock, 901, '/agent two', guid='c2'))
    world.queue.put_nowait(event(clock, 902, '/agent three', guid='c3'))
    await wait_until(lambda: [r['status'] for r in service.status()['recent']][:2] == ['skipped', 'skipped'])
    texts = [text for _chat, text in world.sent]
    assert texts.count(svc.RATE_NOTICE) == 1
    assert len(texts) == 3

    clock.advance(6)
    world.queue.put_nowait(event(clock, 903, '/agent four', guid='c4'))
    await wait_until(lambda: len(world.sent) == 4)
    assert world.sent[-1] == (SELF_CHAT, 'Summary')
    await service.stop()


async def test_identity_revocation_disables_and_stops_without_replying(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    model = FakeModel()
    service = make_service(tmp_path, world, clock, registry=registry, model=model)
    await pair(service, world)
    await service.enable()
    registry.revoke('helper')
    world.queue.put_nowait(event(clock, 900, '/agent check', guid='c1'))
    await wait_until(lambda: service.status()['running'] is False)
    status = service.status()
    assert status['enabled'] is False
    assert status['error'] == svc.ERR_REVOKED
    assert json.loads(settings_path(tmp_path).read_text())['enabled'] is False
    assert [text for _chat, text in world.sent] == ['AgentGate paired.']
    assert model.prompts == []
    await service.stop()


async def test_stale_messages_database_disables_loop(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)
    await pair(service, world)
    world.database = 'db-2'
    await service.enable()
    await wait_until(lambda: service.status()['enabled'] is False and service.status()['running'] is False)
    assert service.status()['error'] == svc.ERR_STALE
    await service.stop()


async def test_loop_crash_sets_safe_error_and_backs_off(tmp_path, registry, monkeypatch):
    monkeypatch.setattr(svc, 'RETRY_BASE_SECONDS', 30)
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)
    await pair(service, world)
    world.opened.clear()  # Ignore the pairing confirmation's bridge; count only the command loop's opens.
    world.crash_messages = 1
    await service.enable()
    await wait_until(lambda: service.status()['error'] == svc.ERR_LOOP)
    await asyncio.sleep(0.1)
    status = service.status()
    assert status['running'] is True
    assert world.opened.count(SELF_CHAT) == 1
    await service.stop()


def live_tasks(name):
    return [t for t in asyncio.all_tasks() if not t.done() and t.get_coro().__name__ == name]


async def test_concurrent_enable_and_disable_never_orphan_a_command_loop(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)
    await pair(service, world)
    await service.enable()
    await asyncio.gather(service.enable(), service.enable(), service.disable(), service.enable())
    assert len(live_tasks('_run_loop')) == 1
    assert service.status()['enabled'] is True
    await service.stop()
    assert live_tasks('_run_loop') == []


async def test_concurrent_pairing_starts_never_orphan_a_pairing_task(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)
    await service.start_pairing('helper')
    await asyncio.gather(service.start_pairing('helper'), service.start_pairing('helper'),
                         service.enable())
    assert len(live_tasks('_pair')) <= 1
    assert len(live_tasks('_run_loop')) <= 1
    await service.stop()
    assert live_tasks('_pair') == [] and live_tasks('_run_loop') == []


class HistoryModel(FakeModel):
    def __init__(self):
        super().__init__()
        self.histories = []
        self.count = 0

    async def plan(self, prompt, history=''):
        self.histories.append(history)
        return await super().plan(prompt, history)

    async def answer(self, prompt, context, history=''):
        self.count += 1
        return f'reply {self.count}'


async def command(world, clock, rowid, text):
    before = len(world.sent)
    world.queue.put_nowait(event(clock, rowid, text, guid=f'h{rowid}'))
    await wait_until(lambda: len(world.sent) == before + 1)
    clock.advance(6)


async def test_replies_see_recent_conversation_in_memory_only(tmp_path, registry):
    world, clock, model = FakeWorld(), Clock(), HistoryModel()
    service = make_service(tmp_path, world, clock, registry=registry, model=model)
    await pair(service, world)
    await service.enable()
    await command(world, clock, 900, '/agent hi there')
    await command(world, clock, 901, '/agent what did I just say?')
    assert model.histories[0] == ''
    assert model.histories[1] == 'User: hi there\nAgentGate: reply 1'
    assert 'hi there' not in json.dumps(service.status())
    for path in (tmp_path / 'config').rglob('*'):
        if path.is_file():
            assert b'hi there' not in path.read_bytes()

    await service.disable()
    await service.enable()
    await command(world, clock, 902, '/agent fresh start')
    assert model.histories[2] == ''
    await service.stop()


async def test_revocation_clears_conversation_memory(tmp_path, registry):
    world, clock, model = FakeWorld(), Clock(), HistoryModel()
    service = make_service(tmp_path, world, clock, registry=registry, model=model)
    await pair(service, world)
    await service.enable()
    await command(world, clock, 900, '/agent remember this')
    registry.revoke('helper')
    world.queue.put_nowait(event(clock, 901, '/agent hi', guid='h901'))
    await wait_until(lambda: service.status()['error'] == svc.ERR_REVOKED)
    assert service._conversation.text(clock()) == ''
    await service.stop()


async def test_conversation_memory_is_bounded_and_expires(tmp_path, registry, monkeypatch):
    world, clock, model = FakeWorld(), Clock(), HistoryModel()
    service = make_service(tmp_path, world, clock, registry=registry, model=model)
    await pair(service, world)
    await service.enable()
    for n in range(12):
        await command(world, clock, 900 + n, '/agent ' + 'x' * 500 + str(n))
    history = model.histories[-1]
    assert len(history) <= svc.CONVERSATION_LIMIT
    assert history.endswith('AgentGate: reply 11')
    assert history.startswith('User: ')
    clock.advance(svc.CONVERSATION_TTL.total_seconds() + 1)
    await command(world, clock, 950, '/agent later')
    assert model.histories[-1] == ''
    await service.stop()


async def test_disable_stops_pairing_as_well_as_the_loop(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)
    await service.start_pairing('helper')
    status = await service.disable()
    assert live_tasks('_pair') == []
    assert status['pairing'] is None


async def test_enable_refuses_a_revoked_agent(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)
    await pair(service, world)
    registry.revoke('helper')
    status = await service.enable()
    assert status['enabled'] is False and status['running'] is False
    assert status['error'] == svc.ERR_REVOKED
    assert live_tasks('_run_loop') == []


async def test_pairing_view_reads_a_consistent_pairing_snapshot(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)

    class PairingThatFinishesOnRead(dict):
        def __getitem__(self, key):
            value = super().__getitem__(key)
            service._pairing = None  # Pairing completes on another task between two reads.
            return value

    service._pairing = PairingThatFinishesOnRead(code='AG-ABCDEF', expires_at=T0 + dt.timedelta(minutes=10))
    assert service._pairing_view()['code'] == 'AG-ABCDEF'


def test_backoff_resets_only_after_a_stream_stayed_healthy():
    connected = T0
    assert svc._next_failures(3, None, T0) == 4
    assert svc._next_failures(3, connected, connected + dt.timedelta(seconds=59)) == 4
    assert svc._next_failures(3, connected, connected + dt.timedelta(seconds=60)) == 1


@pytest.mark.parametrize('text', ['\n/agent hi', ' /agent hi', '\t/agent hi', '/agent\thi', '/agent\nhi',
                                  '/agent', '/agent   ', 'x/agent hi'])
def test_command_requires_exact_agent_prefix(text):
    event = {'chat_id': SELF_CHAT, 'is_group': False, 'is_from_me': True, 'text': text, 'guid': 'g', 'rowid': 1}
    assert svc._parse_command(event, SELF_CHAT) is None


def test_command_request_is_the_trimmed_remainder():
    event = {'chat_id': SELF_CHAT, 'is_group': False, 'is_from_me': True,
             'text': '/agent   check mail  ', 'guid': 'g', 'rowid': 1, 'date': T0}
    assert svc._parse_command(event, SELF_CHAT)[3] == 'check mail'


@pytest.mark.parametrize('error_code', ['send_blocked', 'send_uncertain'])
async def test_poisoned_send_marks_failed_then_restarts_loop_at_tail(tmp_path, registry, error_code):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)
    await pair(service, world)
    await service.enable()
    world.send_error = MessagesBridgeError(error_code)
    world.send_attempts = 0
    world.queue.put_nowait(event(clock, 900, '/agent first', guid='cmd-1'))
    await wait_until(lambda: service.status()['recent'][:1] and service.status()['recent'][0]['status'] == 'failed')
    world.send_error = None
    clock.advance(6)  # Clear the command rate limiter's spacing window.
    world.queue.put_nowait(event(clock, 901, '/agent second', guid='cmd-2'))
    await wait_until(lambda: len(world.sent) == 2)
    assert world.send_attempts == 2
    assert world.sent[-1] == (SELF_CHAT, 'Summary')
    assert world.subscriptions == [0, 900]
    await service.stop()


async def test_stop_cancels_loop_and_pairing(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)
    await pair(service, world)
    await service.enable()
    await service.start_pairing('helper')
    await service.stop()
    status = service.status()
    assert status['running'] is False and status['pairing'] is None


# --- rate limiter ----------------------------------------------------------

def test_command_limiter_spacing_hourly_cap_and_notice_once():
    limiter = svc._CommandLimiter()
    times = [T0 + dt.timedelta(seconds=6 * i) for i in range(30)]
    assert all(limiter.admit(t) == 'accept' for t in times)
    assert limiter.admit(times[-1] + dt.timedelta(seconds=1)) == 'notify'
    assert limiter.admit(times[-1] + dt.timedelta(seconds=2)) == 'drop'
    assert limiter.admit(T0 + dt.timedelta(seconds=3601)) == 'accept'


def test_command_limiter_one_notice_per_burst():
    limiter = svc._CommandLimiter()
    assert limiter.admit(T0) == 'accept'
    assert limiter.admit(T0 + dt.timedelta(seconds=1)) == 'notify'
    assert limiter.admit(T0 + dt.timedelta(seconds=2)) == 'drop'
    assert limiter.admit(T0 + dt.timedelta(seconds=6)) == 'accept'
    assert limiter.admit(T0 + dt.timedelta(seconds=7)) == 'notify'


# --- model adapter ---------------------------------------------------------

class FakeApple:
    def __init__(self, plan=None, answer=None, availability=None):
        self._plan = plan
        self._answer = answer
        self._availability = availability

    def plan(self, prompt, history=''):
        return self._plan

    def answer(self, prompt, context, history=''):
        return self._answer

    def availability(self):
        return self._availability


async def test_async_apple_model_unwraps_success_envelopes():
    data = {'action': 'chat', 'query': '', 'message_id': '', 'owner': '', 'repo': '', 'path': '', 'ref': ''}
    model = AsyncAppleModel(FakeApple(plan={'ok': True, 'data': data},
                                      answer={'ok': True, 'data': {'text': 'hi'}},
                                      availability={'ok': True, 'data': {'available': True, 'reason': 'ok'}}))
    assert await model.plan('p') == data
    assert await model.answer('p', 'ctx') == 'hi'
    assert model.availability() == {'available': True, 'reason': 'ok'}


async def test_async_apple_model_raises_on_failure_envelopes():
    model = AsyncAppleModel(FakeApple(plan={'ok': False, 'code': 'model_timeout', 'reason': 'slow'},
                                      answer={'ok': False, 'code': 'model_failed', 'reason': 'no'},
                                      availability={'ok': False, 'code': 'unsafe_helper', 'reason': 'missing'}))
    with pytest.raises(ModelError):
        await model.plan('p')
    with pytest.raises(ModelError):
        await model.answer('p', 'ctx')
    assert model.availability() == {'available': False, 'reason': 'missing'}
