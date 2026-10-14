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
from broker.approval import ApprovalQueue
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

    async def answer(self, prompt, context, history='', style=''):
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


def make_service(tmp_path, world, clock, *, registry=None, helpers=True, model=None, approvals=None, gmail=None):
    registry = registry or AgentRegistry(tmp_path / 'agents.sqlite3')
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir(exist_ok=True)
    imsg = bin_dir / 'imsg'
    model_helper = bin_dir / 'agentgate-model'
    if helpers:
        for path in (imsg, model_helper):
            path.write_text('#!/bin/sh\n')
            path.chmod(0o700)
    return IMessageService(tmp_path / 'config', registry, gmail or FakeTools(), FakeTools(),
                           imsg_path=imsg, model_helper_path=model_helper,
                           bridge_factory=world.bridge, model=model or FakeModel(), clock=clock,
                           approvals=approvals)


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
    monkeypatch.setattr(svc, 'APPROVAL_POLL_SECONDS', 0.01)


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
        'pairing': None, 'recent': [], 'style': {'messages': 0, 'learning': True, 'needed': svc.MIN_MESSAGES}, 'error': None,
        'approvals': False,
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
        'enabled': False, 'paired': {'chat_id': SELF_CHAT, 'agent_id': 'helper'}, 'halted': None,
        'approvals': False}
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
    assert json.loads(settings_path(tmp_path).read_text()) == {
        'enabled': False, 'paired': None, 'halted': None, 'approvals': False}
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


def write_settings(tmp_path, value):
    (tmp_path / 'config').mkdir(exist_ok=True)
    settings_path(tmp_path).write_text(json.dumps(value))
    settings_path(tmp_path).chmod(0o600)


async def halt_by_stale_database(tmp_path, world, clock, registry):
    service = make_service(tmp_path, world, clock, registry=registry)
    await pair(service, world)
    await service.enable()
    world.database = 'db-2'
    world.crash_messages = 1
    await wait_until(lambda: service.status()['error'] == svc.ERR_STALE and service.status()['running'] is False)
    await service.stop()


async def test_halt_reason_survives_restart(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    await halt_by_stale_database(tmp_path, world, clock, registry)
    restarted = make_service(tmp_path, world, clock, registry=registry)
    await restarted.start()
    status = restarted.status()
    assert status['enabled'] is False and status['running'] is False
    assert status['error'] == svc.ERR_STALE
    assert json.loads(settings_path(tmp_path).read_text())['halted'] == svc.ERR_STALE


async def test_enable_clears_halt_reason(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    await halt_by_stale_database(tmp_path, world, clock, registry)
    world.database = 'db-1'
    restarted = make_service(tmp_path, world, clock, registry=registry)
    status = await restarted.enable()
    assert status['enabled'] is True and status['error'] is None
    assert json.loads(settings_path(tmp_path).read_text())['halted'] is None
    await restarted.stop()


async def test_unpair_clears_halt_reason(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    await halt_by_stale_database(tmp_path, world, clock, registry)
    restarted = make_service(tmp_path, world, clock, registry=registry)
    status = await restarted.unpair()
    assert status['paired'] is False and status['error'] is None
    assert json.loads(settings_path(tmp_path).read_text())['halted'] is None


async def test_completing_a_new_pairing_clears_halt_reason(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    await halt_by_stale_database(tmp_path, world, clock, registry)
    restarted = make_service(tmp_path, world, clock, registry=registry)
    code = (await restarted.start_pairing('helper'))['pairing']['code']
    world.history[SELF_CHAT] = [history_row(501, f'/agent pair {code}')]
    await wait_until(lambda: restarted.status()['pairing'] is None)
    assert restarted.status()['error'] is None
    assert json.loads(settings_path(tmp_path).read_text())['halted'] is None


async def test_settings_without_halted_key_load_as_not_halted(tmp_path, registry):
    write_settings(tmp_path, {'enabled': False, 'paired': {'chat_id': SELF_CHAT, 'agent_id': 'helper'}})
    status = make_service(tmp_path, FakeWorld(), Clock(), registry=registry).status()
    assert status['paired'] is True and status['error'] is None


@pytest.mark.parametrize('halted', ['bogus', '', 7, ['messages_database_changed'], {'code': 'agent_revoked'}])
async def test_invalid_halted_value_is_ignored(tmp_path, registry, halted):
    write_settings(tmp_path, {'enabled': False, 'paired': {'chat_id': SELF_CHAT, 'agent_id': 'helper'},
                              'halted': halted})
    status = make_service(tmp_path, FakeWorld(), Clock(), registry=registry).status()
    assert status['paired'] is True and status['error'] is None


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

    async def answer(self, prompt, context, history='', style=''):
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


class StyleModel(FakeModel):
    def __init__(self):
        super().__init__()
        self.styles = []

    async def answer(self, prompt, context, history='', style=''):
        self.styles.append(style)
        return 'ok'


async def test_learns_texting_style_from_commands_and_can_reset(tmp_path, registry):
    world, clock, model = FakeWorld(), Clock(), StyleModel()
    service = make_service(tmp_path, world, clock, registry=registry, model=model)
    await pair(service, world)
    await service.enable()
    assert service.status()['style'] == {'messages': 0, 'learning': True, 'needed': svc.MIN_MESSAGES}
    for n in range(6):
        await command(world, clock, 900 + n, '/agent lol whats up ' + str(n))
    assert model.styles[0] == ''
    assert 'all lowercase' in model.styles[-1] and 'lol' in model.styles[-1]
    status = service.status()
    assert status['style'] == {'messages': 6, 'learning': False, 'needed': svc.MIN_MESSAGES}
    assert 'lowercase' not in json.dumps(status)
    status = await service.reset_style()
    assert status['style'] == {'messages': 0, 'learning': True, 'needed': svc.MIN_MESSAGES}
    assert status['error'] is None
    await command(world, clock, 920, '/agent hi')
    assert model.styles[-1] == ''
    await service.stop()


async def test_failed_style_reset_is_reported(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry)
    service._style.reset = lambda: False
    status = await service.reset_style()
    assert status['error'] == svc.ERR_STYLE_RESET
    service._error = svc.ERR_REVOKED
    status = await service.reset_style()
    assert status['error'] == svc.ERR_REVOKED


async def test_rate_limited_commands_do_not_teach_style(tmp_path, registry):
    world, clock, model = FakeWorld(), Clock(), StyleModel()
    service = make_service(tmp_path, world, clock, registry=registry, model=model)
    await pair(service, world)
    await service.enable()
    world.queue.put_nowait(event(clock, 900, '/agent one', guid='s1'))
    await wait_until(lambda: len(world.sent) == 2)
    world.queue.put_nowait(event(clock, 901, '/agent two', guid='s2'))
    await wait_until(lambda: any(r['status'] == 'skipped' for r in service.status()['recent']))
    assert service.status()['style']['messages'] == 1
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

    def answer(self, prompt, context, history='', style=''):
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


# --- approvals from iMessage -----------------------------------------------

def email_details(**changes):
    value = {'draft_id': 'd1', 'from': ['me@example.com'], 'to': ['bob@example.com'],
             'cc': ['carol@example.com'], 'bcc': [], 'subject': 'Quarterly numbers', 'date': 'Mon',
             'reply_to': [], 'content_type': 'text/plain', 'headers': ['to', 'cc', 'subject', 'from', 'date'],
             'parts': [{'type': 'text/plain', 'content': 'Hello team'}], 'attachments': [], 'sha256': 'abc'}
    value.update(changes)
    return json.dumps(value)


EMAIL = email_details()
GITHUB = json.dumps({'owner': 'octo', 'repo': 'widgets', 'title': 'Crash on start', 'body': 'Steps follow'})
DASHBOARD_TEXT = 'AgentGate approval needed from helper: open the AgentGate dashboard to review it.'
TOO_LONG_TEXT = ('AgentGate approval needed from helper: too long to review by text '
                 '\u2014 open the AgentGate dashboard.')


def approval_texts(world):
    return [text for _chat, text in world.sent if text.startswith('AgentGate approval:')]


async def approvals_on(tmp_path, world, clock, registry, **kwargs):
    queue = ApprovalQueue()
    service = make_service(tmp_path, world, clock, registry=registry, approvals=queue, **kwargs)
    await pair(service, world)
    await service.enable_approvals()
    await service.enable()
    return service, queue


async def submit(queue, credential='gmail:send', details=EMAIL, agent='helper'):
    task = asyncio.create_task(queue.submit(agent, credential, details=details))
    await asyncio.sleep(0)  # Let the request reach the queue.
    return task


async def test_pending_email_is_announced_once_with_recipients_subject_and_body_preview(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    task = await submit(queue)
    await wait_until(lambda: approval_texts(world))
    await asyncio.sleep(0.05)
    code = queue.get_pending().approval_code
    assert re.fullmatch(r'[0-9a-f]{6}', code)
    assert approval_texts(world) == [
        'AgentGate approval: helper wants gmail:send. Cc: carol@example.com. To: bob@example.com. '
        'Subject: "Quarterly numbers". Body: Hello team. '
        f'Reply "approve {code}" or "deny {code}".']
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


HIDDEN_EMAIL_CONTENT = {
    'long body': {'parts': [{'type': 'text/plain', 'content': 'a' * 300 + 'TAILMARK'}]},
    'html alternative': {'parts': [{'type': 'text/plain', 'content': 'Hello team'},
                                   {'type': 'text/html', 'content': '<p>TAILMARK</p>'}]},
    'html only': {'parts': [{'type': 'text/html', 'content': '<p>TAILMARK</p>'}]},
    'second plain part': {'parts': [{'type': 'text/plain', 'content': 'Hello team'},
                                    {'type': 'text/plain', 'content': 'TAILMARK'}]},
    'attachment': {'attachments': [{'filename': 'TAILMARK.pdf', 'type': 'application/pdf'}]},
    'reply-to': {'reply_to': ['TAILMARK@evil.example']},
    'reply-to unknown': {'reply_to': None},
    'multipart message': {'content_type': 'multipart/mixed'},
    'structure unknown': {'content_type': None},
    'unlisted header': {'headers': ['to', 'subject', 'mail-followup-to']},
    'headers unknown': {'headers': None},
    'display name': {'to': ['TAILMARK Builder <bob@example.com>']},
    'invisible in body': {'parts': [{'type': 'text/plain', 'content': 'Hi\u200bTAILMARK'}]},
    'control in body': {'parts': [{'type': 'text/plain', 'content': 'Hi\x1bTAILMARK'}]},
    'invisible in subject': {'subject': 'Hi\u2066TAILMARK'},
}


@pytest.mark.parametrize('case', sorted(HIDDEN_EMAIL_CONTENT))
async def test_email_with_content_the_text_cannot_show_gets_no_code(tmp_path, registry, case):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    changes = dict(HIDDEN_EMAIL_CONTENT[case])
    details = json.loads(email_details(**changes))
    for key in ('reply_to', 'content_type', 'headers'):
        if key in changes and changes[key] is None:
            del details[key]
    task = await submit(queue, details=json.dumps(details))
    expected = TOO_LONG_TEXT if case == 'long body' else DASHBOARD_TEXT
    await wait_until(lambda: (SELF_CHAT, expected) in world.sent)
    assert approval_texts(world) == []
    assert all('TAILMARK' not in text for _chat, text in world.sent)
    code = queue.get_pending().approval_code
    world.queue.put_nowait(event(clock, 905, f'approve {code}', guid='hidden-1'))
    await wait_until(lambda: (SELF_CHAT, svc.NO_MATCH_REPLY) in world.sent)
    assert not task.done()
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


async def test_long_issue_body_gets_too_long_text_and_no_code(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    github = json.dumps({'owner': 'octo', 'repo': 'widgets', 'title': 'Crash', 'body': 'a' * 300 + 'TAILMARK'})
    task = await submit(queue, 'github:write', github)
    await wait_until(lambda: (SELF_CHAT, TOO_LONG_TEXT) in world.sent)
    assert approval_texts(world) == []
    assert all('TAILMARK' not in text for _chat, text in world.sent)
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


async def test_bcc_is_listed_first_even_with_many_to_addresses(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    to = [f'user{n}@example.com' for n in range(8)]
    task = await submit(queue, details=email_details(to=to, bcc=['hidden@example.com'], cc=[]))
    await wait_until(lambda: approval_texts(world))
    text = approval_texts(world)[0]
    assert text.index('Bcc: hidden@example.com') < text.index('To: user0@example.com')
    assert 'user7@example.com' in text
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


async def test_over_bound_email_gets_dashboard_text_and_no_code(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    to = [f'user{n:02}@example.com' for n in range(30)]
    task = await submit(queue, details=email_details(to=to, bcc=['hidden@example.com']))
    await wait_until(lambda: approval_texts(world) == [] and (SELF_CHAT, TOO_LONG_TEXT) in world.sent)
    assert approval_texts(world) == []
    assert 'approve' not in world.sent[-1][1] and 'hidden@example.com' not in world.sent[-1][1]
    code = queue.get_pending().approval_code
    world.queue.put_nowait(event(clock, 900, f'approve {code}', guid='big-1'))
    await wait_until(lambda: (SELF_CHAT, svc.NO_MATCH_REPLY) in world.sent)
    assert not task.done()
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


async def test_email_body_is_shown_as_written_with_its_line_breaks(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    details = email_details(parts=[{'type': 'text/plain', 'content': 'Hi\n\n  team\tthanks\n'}])
    task = await submit(queue, details=details)
    await wait_until(lambda: approval_texts(world))
    assert 'Body: Hi\n\n  team\tthanks. Reply' in approval_texts(world)[0]
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


@pytest.mark.parametrize('field', ['title', 'body'])
async def test_issue_with_invisible_characters_gets_dashboard_text(tmp_path, registry, field):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    issue = {'owner': 'octo', 'repo': 'widgets', 'title': 'Crash', 'body': 'Steps'}
    issue[field] += '\u200bTAILMARK'
    task = await submit(queue, 'github:write', json.dumps(issue))
    await wait_until(lambda: (SELF_CHAT, DASHBOARD_TEXT) in world.sent)
    assert approval_texts(world) == []
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


@pytest.mark.parametrize('header', ['Alice <a@x.com> (c) <evil@z.com>', 'a@x.com" <evil@z.com>', 'a b@x.com', '', 'ali\u200bce@x.com', 'b\u202e@x.com'])
async def test_unverifiable_recipient_header_gets_dashboard_text_and_no_code(tmp_path, registry, header):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    task = await submit(queue, details=email_details(to=[header]))
    await wait_until(lambda: (SELF_CHAT, DASHBOARD_TEXT) in world.sent)
    assert approval_texts(world) == []
    assert 'approve' not in world.sent[-1][1] and 'evil' not in world.sent[-1][1]
    code = queue.get_pending().approval_code
    world.queue.put_nowait(event(clock, 910, f'approve {code}', guid='hdr-1'))
    await wait_until(lambda: (SELF_CHAT, svc.NO_MATCH_REPLY) in world.sent)
    assert not task.done()
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


async def test_email_with_no_recipients_gets_dashboard_text_and_no_code(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    task = await submit(queue, details=email_details(to=[], cc=[], bcc=[]))
    await wait_until(lambda: (SELF_CHAT, DASHBOARD_TEXT) in world.sent)
    assert approval_texts(world) == []
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


async def test_subject_is_quoted_so_it_cannot_forge_a_recipient_label(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    task = await submit(queue, details=email_details(subject='x. To: boss@corp.com"'))
    await wait_until(lambda: approval_texts(world))
    text = approval_texts(world)[0]
    assert 'To: bob@example.com. Subject: "x. To: boss@corp.com". Body: Hello team.' in text
    assert 'boss@corp.com' not in text.split('Subject:')[0]
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


async def test_github_title_is_quoted_and_inner_quotes_removed(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    github = json.dumps({'owner': 'octo', 'repo': 'widgets', 'title': 'Crash "on" start', 'body': 'Steps follow'})
    task = await submit(queue, 'github:write', github)
    await wait_until(lambda: approval_texts(world))
    assert 'Repo: octo/widgets. Title: "Crash on start". Body: Steps follow.' in approval_texts(world)[0]
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


@pytest.mark.parametrize('owner, repo', [('octo cat', 'widgets'), ('octo', 'widgets: To: boss@corp.com'),
                                         ('octo', 'x' * 101), ('', 'widgets')])
async def test_github_names_outside_the_plain_pattern_get_dashboard_text_and_no_code(tmp_path, registry, owner, repo):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    details = json.dumps({'owner': owner, 'repo': repo, 'title': 'Crash on start', 'body': 'Steps follow'})
    task = await submit(queue, 'github:write', details)
    await wait_until(lambda: (SELF_CHAT, DASHBOARD_TEXT) in world.sent)
    assert approval_texts(world) == []
    assert 'approve' not in world.sent[-1][1] and 'boss' not in world.sent[-1][1]
    code = queue.get_pending().approval_code
    world.queue.put_nowait(event(clock, 920, f'approve {code}', guid='gh-name-1'))
    await wait_until(lambda: (SELF_CHAT, svc.NO_MATCH_REPLY) in world.sent)
    assert not task.done()
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


async def test_pending_github_issue_is_announced_with_repo_title_and_body_preview(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    task = await submit(queue, 'github:write', GITHUB)
    await wait_until(lambda: approval_texts(world))
    code = queue.get_pending().approval_code
    assert approval_texts(world) == [
        f'AgentGate approval: helper wants github:write. Repo: octo/widgets. Title: "Crash on start". '
        f'Body: Steps follow. Reply "approve {code}" or "deny {code}".']
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


async def test_read_permission_is_announced_in_plain_words(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    task = await submit(queue, 'gmail:read', None)
    await wait_until(lambda: approval_texts(world))
    code = queue.get_pending().approval_code
    assert approval_texts(world) == [
        f'AgentGate approval: helper wants to read Gmail. Reply "approve {code}" or "deny {code}".']
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


@pytest.mark.parametrize('credential,details', [
    ('policy.add:widgets', json.dumps({'rules': ['TOPSECRET']})),
    ('gmail:send', None),
    ('mystery:thing', None),
])
async def test_unsummarized_requests_get_dashboard_text_and_no_code(tmp_path, registry, credential, details):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    task = await submit(queue, credential, details)
    await wait_until(lambda: (SELF_CHAT, DASHBOARD_TEXT) in world.sent)
    assert 'TOPSECRET' not in json.dumps(world.sent) and 'approve' not in world.sent[-1][1]
    code = queue.get_pending().approval_code
    world.queue.put_nowait(event(clock, 900, f'approve {code}', guid='dash-1'))
    await wait_until(lambda: (SELF_CHAT, svc.NO_MATCH_REPLY) in world.sent)
    assert not task.done()
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


async def test_operator_requests_are_not_announced(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    task = await submit(queue, agent='operator')
    await asyncio.sleep(0.05)
    assert approval_texts(world) == []
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


@pytest.mark.parametrize('error_code,restarts', [('send_uncertain', True), ('send_blocked', True),
                                                 ('send_failed', False)])
async def test_announcement_send_errors_restart_only_on_restart_codes(tmp_path, registry, error_code, restarts):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    world.send_error = MessagesBridgeError(error_code)
    task = await submit(queue)
    if restarts:
        await wait_until(lambda: len(world.subscriptions) >= 2)
        assert service.status()['running'] is True
    else:
        await asyncio.sleep(0.05)
        assert world.subscriptions == [0]
    assert world.send_attempts >= 1 and service.status()['error'] in (None, svc.ERR_LOOP)
    world.send_error = None
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


async def test_failed_announcement_does_not_crash_loop_and_is_not_approvable(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    world.send_error = MessagesBridgeError('send_failed')
    task = await submit(queue)
    await asyncio.sleep(0.05)
    assert service.status()['running'] is True
    assert approval_texts(world) == []
    world.send_error = None
    code = queue.get_pending().approval_code
    world.queue.put_nowait(event(clock, 900, f'approve {code}', guid='f1'))
    await wait_until(lambda: (SELF_CHAT, svc.NO_MATCH_REPLY) in world.sent)
    assert not task.done()
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


@pytest.mark.parametrize('word,expected,reply', [('approve', True, 'Approved.'), ('deny', False, 'Denied.')])
async def test_approve_and_deny_resolve_the_notified_request(tmp_path, registry, word, expected, reply):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    task = await submit(queue)
    await wait_until(lambda: approval_texts(world))
    code = queue.get_pending().approval_code
    world.queue.put_nowait(event(clock, 900, f'{word} {code}', guid='r1'))
    assert await asyncio.wait_for(task, 2) is expected
    await wait_until(lambda: (SELF_CHAT, reply) in world.sent)
    await service.stop()


async def test_approval_reply_ignores_case_and_surrounding_whitespace(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    task = await submit(queue)
    await wait_until(lambda: approval_texts(world))
    code = queue.get_pending().approval_code
    world.queue.put_nowait(event(clock, 900, f'  APPROVE {code.upper()}  ', guid='r2'))
    assert await asyncio.wait_for(task, 2) is True
    await service.stop()


@pytest.mark.parametrize('text', ['approve {code} please', 'approve {code}x', 'approve', 'approve 12345',
                                  'maybe {code}', 'approve {code}\n{code}'])
async def test_malformed_approval_text_is_ignored(tmp_path, registry, text):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    task = await submit(queue)
    await wait_until(lambda: approval_texts(world))
    code = queue.get_pending().approval_code
    world.queue.put_nowait(event(clock, 900, text.format(code=code), guid='m1'))
    await asyncio.sleep(0.05)
    assert not task.done()
    assert [t for _chat, t in world.sent if t.startswith(('Approved', 'Denied', 'No pending'))] == []
    assert service.status()['recent'] == []
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


async def test_wrong_code_is_rejected_and_request_stays_pending(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    task = await submit(queue)
    await wait_until(lambda: approval_texts(world))
    code = queue.get_pending().approval_code
    wrong = '000000' if code != '000000' else '111111'
    world.queue.put_nowait(event(clock, 900, f'approve {wrong}', guid='w1'))
    await wait_until(lambda: (SELF_CHAT, svc.NO_MATCH_REPLY) in world.sent)
    assert not task.done()
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


async def test_request_that_was_never_announced_cannot_be_approved(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    task = await submit(queue, agent='operator')
    code = queue.get_pending().approval_code
    world.queue.put_nowait(event(clock, 900, f'approve {code}', guid='u1'))
    await wait_until(lambda: (SELF_CHAT, svc.NO_MATCH_REPLY) in world.sent)
    assert not task.done()
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


async def test_duplicate_echo_resolves_and_replies_once(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    task = await submit(queue)
    await wait_until(lambda: approval_texts(world))
    code = queue.get_pending().approval_code
    world.queue.put_nowait(event(clock, 900, f'approve {code}', guid='e1'))
    world.queue.put_nowait(event(clock, 900, f'approve {code}', guid='e1'))
    assert await asyncio.wait_for(task, 2) is True
    await asyncio.sleep(0.05)
    assert [t for _chat, t in world.sent].count('Approved.') == 1
    await service.stop()


async def test_rate_limited_approval_reply_is_not_applied(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    world.queue.put_nowait(event(clock, 899, '/agent first', guid='c0'))
    await wait_until(lambda: len(world.sent) == 2)
    task = await submit(queue)
    await wait_until(lambda: approval_texts(world))
    code = queue.get_pending().approval_code
    world.queue.put_nowait(event(clock, 900, f'approve {code}', guid='rl1'))
    await wait_until(lambda: (SELF_CHAT, svc.RATE_NOTICE) in world.sent)
    assert not task.done()
    clock.advance(6)
    world.queue.put_nowait(event(clock, 901, f'approve {code}', guid='rl2'))
    assert await asyncio.wait_for(task, 2) is True
    await service.stop()


async def test_disabled_approvals_send_nothing_and_ignore_replies(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    await service.disable_approvals()
    assert service.status()['running'] is True
    task = await submit(queue)
    await asyncio.sleep(0.05)
    assert approval_texts(world) == []
    code = queue.get_pending().approval_code
    world.queue.put_nowait(event(clock, 900, f'approve {code}', guid='d1'))
    await asyncio.sleep(0.05)
    assert not task.done()
    assert [t for _chat, t in world.sent] == ['AgentGate paired.']
    assert service.status()['recent'] == []
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


@pytest.mark.parametrize('how', ['stop', 'disable', 'unpair'])
async def test_stopping_the_loop_or_unpairing_stops_notifications(tmp_path, registry, how):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    await getattr(service, how)()
    task = await submit(queue)
    await asyncio.sleep(0.05)
    assert approval_texts(world) == []
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


async def test_halting_stops_notifications(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    world.database = 'db-2'
    world.crash_messages = 1
    await wait_until(lambda: service.status()['error'] == svc.ERR_STALE)
    task = await submit(queue)
    await asyncio.sleep(0.05)
    assert approval_texts(world) == []
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


class ApprovalGmail:
    """Gmail stand-in whose read waits on an approval, as an 'ask'-level read does."""

    def __init__(self, approvals):
        self._approvals = approvals

    async def execute(self, agent, resource, operation, *, identity_guard, **args):
        await self._approvals.submit(agent, resource)
        return {'ok': True, 'data': {'messages': []}}


class UnreadModel(FakeModel):
    async def plan(self, prompt, history=''):
        return {'action': 'gmail_unread'}


async def test_command_awaiting_approval_does_not_block_the_approve_reply(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    queue = ApprovalQueue()
    service = make_service(tmp_path, world, clock, registry=registry, approvals=queue,
                           gmail=ApprovalGmail(queue), model=UnreadModel())
    await pair(service, world)
    await service.enable_approvals()
    await service.enable()
    world.queue.put_nowait(event(clock, 900, '/agent check my mail', guid='cmd-1'))
    await wait_until(lambda: approval_texts(world))
    assert [t for _chat, t in world.sent if not t.startswith('AgentGate approval')] == ['AgentGate paired.']
    clock.advance(6)  # The command was accepted a moment ago; clear the reply's rate-limit spacing.
    code = queue.get_pending().approval_code
    world.queue.put_nowait(event(clock, 901, f'approve {code}', guid='ap-1'))
    await wait_until(lambda: (SELF_CHAT, 'Approved.') in world.sent and (SELF_CHAT, 'Summary') in world.sent)
    assert world.sent.index((SELF_CHAT, 'Approved.')) < world.sent.index((SELF_CHAT, 'Summary'))
    await service.stop()


async def test_approvals_setting_defaults_off_and_persists(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry, approvals=ApprovalQueue())
    assert service.status()['approvals'] is False
    await pair(service, world)
    assert json.loads(settings_path(tmp_path).read_text())['approvals'] is False
    assert (await service.enable_approvals())['approvals'] is True
    assert json.loads(settings_path(tmp_path).read_text()) == {
        'enabled': False, 'paired': {'chat_id': SELF_CHAT, 'agent_id': 'helper'}, 'halted': None,
        'approvals': True}
    restarted = make_service(tmp_path, world, clock, registry=registry, approvals=ApprovalQueue())
    assert restarted.status()['approvals'] is True
    await restarted.enable()
    assert json.loads(settings_path(tmp_path).read_text())['approvals'] is True
    await restarted.disable()
    assert json.loads(settings_path(tmp_path).read_text())['approvals'] is True
    assert (await restarted.disable_approvals())['approvals'] is False
    assert json.loads(settings_path(tmp_path).read_text())['approvals'] is False
    await service.stop()
    await restarted.stop()


async def test_enable_approvals_requires_pairing(tmp_path, registry):
    service = make_service(tmp_path, FakeWorld(), Clock(), registry=registry, approvals=ApprovalQueue())
    status = await service.enable_approvals()
    assert status['approvals'] is False and status['error'] == svc.ERR_NOT_PAIRED
    assert not settings_path(tmp_path).exists()


async def test_unpair_and_new_pairing_reset_approvals(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry, approvals=ApprovalQueue())
    await pair(service, world)
    await service.enable_approvals()
    code = (await service.start_pairing('helper'))['pairing']['code']
    world.history[SELF_CHAT] = [history_row(502, f'/agent pair {code}')]
    await wait_until(lambda: service.status()['paired'] and service.status()['pairing'] is None)
    assert json.loads(settings_path(tmp_path).read_text())['approvals'] is False
    await service.enable_approvals()
    assert (await service.unpair())['approvals'] is False
    assert json.loads(settings_path(tmp_path).read_text())['approvals'] is False


async def test_settings_without_approvals_key_load_as_off(tmp_path, registry):
    write_settings(tmp_path, {'enabled': False, 'paired': {'chat_id': SELF_CHAT, 'agent_id': 'helper'},
                              'halted': None})
    status = make_service(tmp_path, FakeWorld(), Clock(), registry=registry, approvals=ApprovalQueue()).status()
    assert status['paired'] is True and status['error'] is None and status['approvals'] is False


@pytest.mark.parametrize('value', ['yes', 1, None, [True], {'on': True}, 'true'])
async def test_invalid_approvals_value_is_off_and_keeps_file_readable(tmp_path, registry, value):
    write_settings(tmp_path, {'enabled': False, 'paired': {'chat_id': SELF_CHAT, 'agent_id': 'helper'},
                              'halted': None, 'approvals': value})
    status = make_service(tmp_path, FakeWorld(), Clock(), registry=registry, approvals=ApprovalQueue()).status()
    assert status['paired'] is True and status['error'] is None and status['approvals'] is False


async def test_approval_decisions_are_audited_as_operator_actions(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    audited = []

    class RecordingAudit:
        def log(self, **entry):
            audited.append(entry)

    service._audit = RecordingAudit()
    task = await submit(queue)
    await wait_until(lambda: approval_texts(world))
    code = queue.get_pending().approval_code
    world.queue.put_nowait(event(clock, 900, f'deny {code}', guid='a1'))
    assert await asyncio.wait_for(task, 2) is False
    await wait_until(lambda: audited)
    assert audited[0]['agent'] == 'operator'
    assert audited[0]['credential_requested'] == 'gmail:send'
    assert audited[0]['policy_matched'] == 'imessage-approval'
    assert audited[0]['decision'] == 'denied'
    await service.stop()


async def test_approval_reply_halts_when_the_agent_was_revoked(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    task = await submit(queue)
    await wait_until(lambda: approval_texts(world))
    code = queue.get_pending().approval_code
    registry.revoke('helper')
    world.queue.put_nowait(event(clock, 900, f'approve {code}', guid='rv-1'))
    await wait_until(lambda: service.status()['error'] == svc.ERR_REVOKED)
    assert not task.done() and service.status()['running'] is False
    assert (SELF_CHAT, 'Approved.') not in world.sent
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


async def test_unpair_forgets_announced_requests(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    task = await submit(queue)
    await wait_until(lambda: approval_texts(world))
    request_id = queue.get_pending().request_id
    assert request_id in service._delivered_requests
    await service.unpair()
    assert request_id not in service._delivered_requests and request_id not in service._attempted_requests
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


async def test_pairing_completion_forgets_announced_requests(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    task = await submit(queue)
    await wait_until(lambda: approval_texts(world))
    request_id = queue.get_pending().request_id
    service._delivered_requests.add('stale')
    service._complete_pairing(SELF_CHAT, 'helper', 'identity-2')
    assert request_id not in service._delivered_requests and 'stale' not in service._delivered_requests
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


async def test_approval_setting_changes_are_audited(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service = make_service(tmp_path, world, clock, registry=registry, approvals=ApprovalQueue())
    audited = []

    class RecordingAudit:
        def log(self, **entry):
            audited.append(entry)

    service._audit = RecordingAudit()
    await pair(service, world)
    await service.enable_approvals()
    await service.disable_approvals()
    assert [(e['agent'], e['credential_requested'], e['decision']) for e in audited] == [
        ('operator', 'imessage:approvals-enable', 'completed'),
        ('operator', 'imessage:approvals-disable', 'completed')]
    await service.stop()


async def test_non_list_recipient_fields_do_not_crash_the_announcement(tmp_path, registry):
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    task = await submit(queue, details=email_details(to='bob@example.com', cc={'x': 1}, bcc=None))
    await wait_until(lambda: (SELF_CHAT, DASHBOARD_TEXT) in world.sent)
    assert approval_texts(world) == []
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()


async def test_draft_built_like_the_draft_tool_gets_a_code(tmp_path, registry):
    import base64
    from email.message import EmailMessage
    from broker.integrations.gmail import describe_message
    message = EmailMessage()
    message['To'] = 'bob@example.com'
    message['Subject'] = 'Quarterly numbers'
    message['Cc'] = 'carol@example.com'
    message.set_content('Hello team\nSee you Monday')
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode('ascii')
    world, clock = FakeWorld(), Clock()
    service, queue = await approvals_on(tmp_path, world, clock, registry)
    task = await submit(queue, details=json.dumps({'draft_id': 'd1', **describe_message(raw)}))
    await wait_until(lambda: approval_texts(world))
    assert ('Cc: carol@example.com. To: bob@example.com. Subject: "Quarterly numbers". '
            'Body: Hello team\nSee you Monday. Reply') in approval_texts(world)[0]
    queue.resolve(queue.get_pending(), False)
    await task
    await service.stop()
