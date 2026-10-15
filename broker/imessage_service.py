"""Owner-facing iMessage agent service: self-chat pairing, enablement, and the paired command loop.

The service owns the persisted pairing settings (config_dir/imessage.json, private 0600), runs at
most one pairing session and one command loop at a time, and fails closed: anything unreadable,
stale, revoked, or unavailable disables the loop rather than replying.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import functools
import hmac
import json
import os
import secrets
import stat
import tempfile
import unicodedata
from collections import deque
from pathlib import Path

from broker.apple_model import AppleModel
from broker.imessage_agent import APPROVAL_REPLY, ReadOnlyMessageAgent
from broker.imessage_approval_text import announcement
from broker.imessage_bridge import MessagesBridge, MessagesBridgeError, is_self_chat, verify_helper
from broker.imessage_state import MessageLedger, MessageLedgerError
from broker.imessage_style import MIN_MESSAGES, TextingStyle

PAIRING_POLL_SECONDS = 2.0
APPROVAL_POLL_SECONDS = 2.0
APPROVAL_TRACK_LIMIT = 256
PAIRING_TTL = dt.timedelta(minutes=10)
PAIRING_HISTORY_LIMIT = 10
CHAT_LIST_LIMIT = 25
RETRY_BASE_SECONDS = 5.0
RETRY_CAP_SECONDS = 300.0
RATE_WINDOW = dt.timedelta(seconds=5)
MODEL_TTL = dt.timedelta(seconds=60)
STABLE_AFTER = dt.timedelta(seconds=60)
HOURLY_WINDOW = dt.timedelta(hours=1)
HOURLY_LIMIT = 30
RECENT_LIMIT = 20
CONVERSATION_TURNS = 6
CONVERSATION_LIMIT = 2000
CONVERSATION_TTL = dt.timedelta(minutes=30)
SETTINGS_FILE = 'imessage.json'
STYLE_FILE = 'imessage-style.json'
SETTINGS_LIMIT = 4096
PAIRED_CONFIRMATION = 'AgentGate paired.'
RATE_NOTICE = 'AgentGate is handling recent requests. Please wait a moment before sending another.'
CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
COMMAND_PREFIX = '/agent '
NO_MATCH_REPLY = 'No pending approval matches that code.'
APPROVED_REPLY = 'Approved.'
DENIED_REPLY = 'Denied.'

ERR_UNAVAILABLE = 'unavailable'
ERR_NOT_PAIRED = 'not_paired'
ERR_MODEL = 'model_unavailable'
ERR_EXPIRED = 'pairing_expired'
ERR_UNREADABLE = 'settings_unreadable'
ERR_SAVE = 'settings_not_saved'
ERR_LOOP = 'loop_failed'
ERR_REVOKED = 'agent_revoked'
ERR_STALE = 'messages_database_changed'
ERR_LEDGER = 'ledger_unavailable'
ERR_STYLE_RESET = 'style_not_reset'
RESTART_CODES = frozenset({'send_uncertain', 'send_blocked'})
HALT_CODES = frozenset({ERR_STALE, ERR_REVOKED})


class ModelError(Exception):
    """The local model helper returned a failure envelope."""


class _Restart(Exception):
    """Restart the bridge, and with it the imsg helper, resuming after the current cursor."""


def _serialized(method):
    """Run one service mutation at a time, so concurrent requests cannot orphan a loop or pairing task."""
    @functools.wraps(method)
    async def wrapper(self, *args, **kwargs):
        async with self._lock:
            return await method(self, *args, **kwargs)
    return wrapper


def _next_failures(failures, connected_at, now):
    """Failure count after a dropped stream. Only a stream that stayed up for STABLE_AFTER starts a fresh backoff."""
    if connected_at is not None and now - connected_at >= STABLE_AFTER:
        return 1
    return failures + 1


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _data(result):
    if not isinstance(result, dict) or result.get('ok') is not True or not isinstance(result.get('data'), dict):
        code = result.get('code') if isinstance(result, dict) else None
        raise ModelError(code if isinstance(code, str) else 'model_failed')
    return result['data']


class UnavailableIMessageService:
    """Stands in for IMessageService when its state cannot be opened, so the rest of the broker still starts."""

    def __init__(self, error):
        self._error = error

    def status(self):
        return {'available': False, 'enabled': False, 'paired': False, 'running': False, 'approvals': False,
                'agent': None,
                'model': {'available': False, 'reason': 'iMessage is not available on this broker.'},
                'pairing': None, 'recent': [], 'style': {'messages': 0, 'learning': True, 'needed': MIN_MESSAGES},
                'error': self._error}

    async def snapshot(self):
        return self.status()

    async def start(self):
        return None

    async def stop(self):
        return None

    async def start_pairing(self, agent_id):
        return self.status()

    async def cancel_pairing(self):
        return self.status()

    async def enable(self):
        return self.status()

    async def disable(self):
        return self.status()

    async def unpair(self):
        return self.status()

    async def reset_style(self):
        return self.status()

    async def enable_approvals(self):
        return self.status()

    async def disable_approvals(self):
        return self.status()


class AsyncAppleModel:
    """Async adapter over AppleModel. Blocking helper calls run in a worker thread."""

    def __init__(self, apple):
        self._apple = apple

    async def plan(self, prompt, history=''):
        return _data(await asyncio.to_thread(self._apple.plan, prompt, history))

    async def answer(self, prompt, context, history='', style=''):
        data = _data(await asyncio.to_thread(self._apple.answer, prompt, context, history, style))
        text = data.get('text')
        if not isinstance(text, str):
            raise ModelError('model_failed')
        return text

    def availability(self):
        result = self._apple.availability()
        if isinstance(result, dict) and result.get('ok') is True and isinstance(result.get('data'), dict):
            data = result['data']
            return {'available': data.get('available') is True, 'reason': str(data.get('reason', ''))[:200]}
        reason = result.get('reason') if isinstance(result, dict) else None
        return {'available': False, 'reason': reason if isinstance(reason, str) else 'Local model unavailable.'}


class _CommandLimiter:
    """Accepted commands are at least RATE_WINDOW apart and at most HOURLY_LIMIT per hour.

    Refused commands yield one 'notify' per burst; later refusals in the same burst are 'drop'.
    """

    def __init__(self):
        self._accepted = deque()
        self._noticed = False

    def admit(self, now: dt.datetime) -> str:
        while self._accepted and self._accepted[0] <= now - HOURLY_WINDOW:
            self._accepted.popleft()
        too_fast = bool(self._accepted) and now - self._accepted[-1] < RATE_WINDOW
        if not too_fast and len(self._accepted) < HOURLY_LIMIT:
            self._accepted.append(now)
            self._noticed = False
            return 'accept'
        if self._noticed:
            return 'drop'
        self._noticed = True
        return 'notify'


def _valid_settings(value) -> bool:
    if not isinstance(value, dict) or not {'enabled', 'paired'} <= set(value) <= {'enabled', 'paired', 'halted', 'approvals'}:
        return False
    if type(value['enabled']) is not bool:
        return False
    paired = value['paired']
    if paired is None:
        return value['enabled'] is False
    return (isinstance(paired, dict) and set(paired) == {'chat_id', 'agent_id'}
            and type(paired['chat_id']) is int and paired['chat_id'] > 0
            and isinstance(paired['agent_id'], str) and paired['agent_id'] != '')


def _read_settings(path: Path):
    """Return (settings, error). A missing file means unpaired; anything unsafe fails closed."""
    empty = {'enabled': False, 'paired': None, 'halted': None, 'approvals': False}
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    except FileNotFoundError:
        return empty, None
    except OSError:
        return empty, ERR_UNREADABLE
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077):
            return empty, ERR_UNREADABLE
        raw = os.read(fd, SETTINGS_LIMIT + 1)
    except OSError:
        return empty, ERR_UNREADABLE
    finally:
        os.close(fd)
    if len(raw) > SETTINGS_LIMIT:
        return empty, ERR_UNREADABLE
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return empty, ERR_UNREADABLE
    if not _valid_settings(value):
        return empty, ERR_UNREADABLE
    halted = value.get('halted')
    value['halted'] = halted if isinstance(halted, str) and halted in HALT_CODES else None
    value['approvals'] = value.get('approvals') is True
    return value, None


def _write_settings(config_dir: Path, path: Path, settings) -> None:
    config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=config_dir, prefix='.imessage-', suffix='.tmp')
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(json.dumps(settings, sort_keys=True).encode())
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _helper_ready(path: Path) -> bool:
    try:
        verify_helper(path)
    except MessagesBridgeError:
        return False
    return True


def _self_chat_text(event, chat_id):
    """(message_id, rowid, date, text) for plain text I sent in the paired self-chat, else None."""
    if not isinstance(event, dict):
        return None
    if event.get('chat_id') != chat_id or event.get('is_group') is not False or event.get('is_from_me') is not True:
        return None
    text = event.get('text')
    message_id = event.get('guid')
    if not isinstance(text, str) or not isinstance(message_id, str) or not message_id:
        return None
    return message_id, event.get('rowid'), event.get('date'), text


def _parse_command(event, chat_id):
    """(message_id, rowid, date, request) for a paired-chat '/agent <request>' from me, else None."""
    parsed = _self_chat_text(event, chat_id)
    if parsed is None:
        return None
    message_id, rowid, date, text = parsed
    if not text.startswith(COMMAND_PREFIX):
        return None
    request = text[len(COMMAND_PREFIX):].strip()
    if not request or APPROVAL_REPLY.fullmatch(request):
        return None
    return message_id, rowid, date, request


def _parse_approval(event, chat_id):
    """(message_id, rowid, date, verb, code) for a paired-chat 'approve|deny <code>' from me, else None."""
    parsed = _self_chat_text(event, chat_id)
    if parsed is None:
        return None
    message_id, rowid, date, text = parsed
    # '/agent approve <code>' is a natural slip after pairing with '/agent pair'; it means the same thing.
    if text.startswith(COMMAND_PREFIX):
        text = text[len(COMMAND_PREFIX):]
    match = APPROVAL_REPLY.fullmatch(text)
    if match is None:
        return None
    return message_id, rowid, date, match.group(1).lower(), match.group(2).lower()


def _clean(text: str) -> str:
    """Visible text only: control characters become spaces, invisible format characters are dropped."""
    pieces = []
    for character in text:
        category = unicodedata.category(character)
        if category == 'Cf':
            continue
        pieces.append(' ' if category == 'Cc' else character)
    return ' '.join(''.join(pieces).split())


class _RecentIds:
    """Bounded set of request ids, oldest evicted first."""

    def __init__(self, limit):
        self._order = deque()
        self._ids = set()
        self._limit = limit

    def add(self, value):
        if value in self._ids:
            return
        if len(self._order) >= self._limit:
            self._ids.discard(self._order.popleft())
        self._order.append(value)
        self._ids.add(value)

    def __contains__(self, value):
        return value in self._ids


class _Conversation:
    """Recent exchanges in the paired chat, so replies can follow the thread. Memory only, never saved."""

    def __init__(self):
        self._turns = []
        self._last = None

    def text(self, now):
        if self._last is None or now - self._last > CONVERSATION_TTL:
            self.clear()
            return ''
        blocks, total = [], 0
        for user, reply in reversed(self._turns):
            block = f'User: {user}\nAgentGate: {reply}'
            total += len(block) + (1 if blocks else 0)
            if total > CONVERSATION_LIMIT:
                break
            blocks.append(block)
        return '\n'.join(reversed(blocks))

    def add(self, user, reply, now):
        self._turns.append((user, reply))
        del self._turns[:-CONVERSATION_TURNS]
        self._last = now

    def clear(self):
        self._turns.clear()
        self._last = None


class _Halt(Exception):
    """Stops the command loop and disables the agent with a safe reason code."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


class IMessageService:
    def __init__(self, config_dir, registry, gmail_tools, github_tools, *, imsg_path, model_helper_path,
                 audit=None, bridge_factory=None, model=None, clock=None, approvals=None):
        self._config_dir = Path(config_dir).expanduser().absolute()
        self._settings_path = self._config_dir / SETTINGS_FILE
        self._registry = registry
        self._imsg_path = Path(imsg_path).expanduser().absolute()
        self._model_helper_path = Path(model_helper_path).expanduser().absolute()
        self._ledger = MessageLedger(registry)
        self._bridge_factory = bridge_factory or self._default_bridge
        if model is None:
            model = AsyncAppleModel(AppleModel(self._model_helper_path))
        self._model = model
        self._agent = ReadOnlyMessageAgent(audit, gmail_tools, github_tools, model)
        self._audit = audit
        self._approvals = approvals
        self._forget_requests()
        self._cursor = 0
        self._clock = clock or _utcnow
        self._limiter = _CommandLimiter()
        self._conversation = _Conversation()
        self._style = TextingStyle(self._config_dir / STYLE_FILE)
        self._settings, self._error = _read_settings(self._settings_path)
        self._unreadable = self._error == ERR_UNREADABLE
        if self._settings['halted'] and self._settings['paired'] and not self._settings['enabled']:
            self._error = self._settings['halted']
        self._loop_task = None
        self._pairing = None
        self._pairing_task = None
        self._lock = asyncio.Lock()
        self._model_value = None
        self._model_checked_at = None

    # --- status ----------------------------------------------------------------

    async def snapshot(self):
        """Status for the operator app. Refreshes an expired model check in a worker thread, never on the loop."""
        await self._refresh_model()
        return self.status()

    def status(self):
        paired = self._paired()
        return {
            'available': self._helpers_ready(),
            'enabled': self._settings['enabled'] and not self._unreadable,
            'paired': paired is not None,
            'running': self._loop_running(),
            'approvals': self._approvals_on(),
            'agent': {'id': paired['agent_id'], 'name': paired['agent_id']} if paired else None,
            'model': self._model_availability(),
            'pairing': self._pairing_view(),
            'recent': self._recent(),
            'style': {'messages': self._style.count(), 'learning': self._style.count() < MIN_MESSAGES,
                      'needed': MIN_MESSAGES},
            'error': self._error,
        }

    def _paired(self):
        return None if self._unreadable else self._settings['paired']

    def _forget_requests(self):
        """Requests announced before a pairing change are no longer approvable over iMessage."""
        self._attempted_requests = _RecentIds(APPROVAL_TRACK_LIMIT)
        self._delivered_requests = _RecentIds(APPROVAL_TRACK_LIMIT)

    def _audit_operator(self, resource, policy, decision):
        if self._audit is not None:
            self._audit.log(agent='operator', credential_requested=resource, policy_matched=policy,
                            decision=decision, mode='imessage', token_expiry=None)

    def _approvals_on(self):
        return self._approvals is not None and not self._unreadable and self._settings['approvals'] is True

    def _loop_running(self):
        return self._loop_task is not None and not self._loop_task.done()

    def _pairing_view(self):
        pairing = self._pairing
        if pairing is None:
            return None
        return {'code': pairing['code'], 'expires_at': pairing['expires_at'].isoformat()}

    def _recent(self):
        try:
            return self._ledger.list_recent(RECENT_LIMIT)
        except MessageLedgerError:
            return []

    def _model_availability(self):
        """The last checked model state. Never runs the helper, so it is safe to call from the event loop."""
        if self._model_value is None:
            return {'available': False, 'reason': 'The local model has not been checked yet.'}
        return self._model_value

    async def _refresh_model(self):
        """Check the local model in a worker thread, at most once per MODEL_TTL."""
        now = self._clock()
        if self._model_checked_at is not None and now - self._model_checked_at < MODEL_TTL:
            return
        try:
            result = await asyncio.to_thread(self._model.availability)
            self._model_value = {'available': result.get('available') is True,
                                 'reason': str(result.get('reason', ''))[:200]}
        except Exception:
            self._model_value = {'available': False, 'reason': 'The local model could not be checked.'}
        self._model_checked_at = now

    def _model_ready(self):
        return self._model_availability()['available']

    def _helpers_ready(self):
        return _helper_ready(self._imsg_path) and _helper_ready(self._model_helper_path)

    def _agent_active(self, agent_id) -> bool:
        try:
            return any(a.get('id') == agent_id and a.get('status') == 'active'
                       for a in self._registry.list_agents())
        except Exception:
            return False

    def _can_run(self) -> bool:
        return (not self._unreadable and self._settings['enabled'] and self._paired() is not None
                and self._model_ready() and self._helpers_ready())

    def _default_bridge(self, chat_id):
        if chat_id is None:
            return MessagesBridge.for_pairing(self._imsg_path)
        return MessagesBridge(self._imsg_path, paired_chat_id=chat_id)

    def _database_identity(self):
        return self._bridge_factory(None).database_identity()

    def _settings_with(self, **changes):
        settings = {'enabled': self._settings['enabled'], 'paired': self._settings['paired'],
                    'halted': self._settings['halted'], 'approvals': self._settings['approvals']}
        settings.update(changes)
        return settings

    def _save(self, settings) -> bool:
        try:
            _write_settings(self._config_dir, self._settings_path, settings)
        except OSError:
            self._error = ERR_SAVE
            return False
        self._settings = settings
        self._unreadable = False
        return True

    # --- pairing ---------------------------------------------------------------

    @_serialized
    async def start_pairing(self, agent_id):
        if not isinstance(agent_id, str) or not self._agent_active(agent_id):
            raise ValueError('Choose an active agent to pair.')
        await self._stop_loop()
        await self._cancel_pairing()
        if not self._unreadable and self._settings['enabled']:
            self._save(self._settings_with(enabled=False))
        self._error = None
        if not self._helpers_ready():
            self._error = ERR_UNAVAILABLE
            return self.status()
        code = 'AG-' + ''.join(secrets.choice(CODE_ALPHABET) for _ in range(6))
        expires = self._clock() + PAIRING_TTL
        self._pairing = {'code': code, 'expires_at': expires}
        self._pairing_task = asyncio.create_task(self._pair(code, agent_id, expires))
        return self.status()

    @_serialized
    async def cancel_pairing(self):
        await self._cancel_pairing()
        return self.status()

    async def _cancel_pairing(self):
        task, self._pairing_task = self._pairing_task, None
        self._pairing = None
        if task is not None:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    def _finish_pairing(self, error):
        self._pairing = None
        self._error = error

    async def _pair(self, code, agent_id, expires):
        bridge = self._bridge_factory(None)
        try:
            chat_id, identity = await self._await_pairing(bridge, code, agent_id, expires)
        except MessagesBridgeError:
            self._finish_pairing(ERR_UNAVAILABLE)
            return
        finally:
            await bridge.close()
        if chat_id is None:
            return
        if self._complete_pairing(chat_id, agent_id, identity):
            await self._confirm(chat_id)

    async def _await_pairing(self, bridge, code, agent_id, expires):
        """Poll discovery-only until the exact code appears in a self-chat. Returns (chat_id, identity)."""
        await bridge.start()
        while True:
            if self._clock() >= expires:
                self._finish_pairing(ERR_EXPIRED)
                return None, None
            if not self._agent_active(agent_id):
                self._finish_pairing(ERR_REVOKED)
                return None, None
            chat_id = await self._find_pairing_chat(bridge, code)
            if chat_id is not None:
                return chat_id, bridge.database_identity()
            await asyncio.sleep(PAIRING_POLL_SECONDS)

    async def _find_pairing_chat(self, bridge, code):
        expected = f'/agent pair {code}'
        for chat_id in await bridge.list_chats(limit=CHAT_LIST_LIMIT):
            try:
                chat = await bridge.get_chat(chat_id)
                if not is_self_chat(chat):
                    continue
                rows = await bridge.history(chat_id, limit=PAIRING_HISTORY_LIMIT)
            except MessagesBridgeError:
                continue
            if any(row.get('is_from_me') is True and row.get('text') == expected for row in rows):
                return chat_id
        return None

    def _complete_pairing(self, chat_id, agent_id, identity):
        self._pairing = None
        try:
            self._ledger.baseline(str(chat_id), identity, self._clock())
        except MessageLedgerError:
            self._error = ERR_UNAVAILABLE
            return False
        # A new pairing starts with approvals off, so nothing is announced until the owner turns it on again.
        if not self._save({'enabled': False, 'paired': {'chat_id': chat_id, 'agent_id': agent_id}, 'halted': None,
                           'approvals': False}):
            return False
        self._forget_requests()
        self._error = None
        return True

    async def _confirm(self, chat_id):
        """Best-effort confirmation; the pairing is already saved if this fails."""
        bridge = self._bridge_factory(chat_id)
        try:
            await bridge.start()
            await bridge.send_text(PAIRED_CONFIRMATION)
        except MessagesBridgeError:
            pass
        finally:
            await bridge.close()

    @_serialized
    async def reset_style(self):
        if not self._style.reset():
            # Keep a more important error, such as why the loop halted, on screen.
            self._error = self._error or ERR_STYLE_RESET
        elif self._error == ERR_STYLE_RESET:
            self._error = None
        return self.status()

    @_serialized
    async def unpair(self):
        await self._stop_loop()
        await self._cancel_pairing()
        self._forget_requests()
        if self._save({'enabled': False, 'paired': None, 'halted': None, 'approvals': False}):
            self._error = None
        return self.status()

    # --- approvals -------------------------------------------------------------

    @_serialized
    async def enable_approvals(self):
        """Announce pending approvals in the paired chat; replies 'approve <code>' or 'deny <code>' decide them."""
        if self._paired() is None:
            self._error = ERR_NOT_PAIRED
            return self.status()
        saved = self._save(self._settings_with(approvals=True))
        self._audit_operator('imessage:approvals-enable', 'operator-settings', 'completed' if saved else 'failed')
        return self.status()

    @_serialized
    async def disable_approvals(self):
        if not self._unreadable and self._settings['approvals']:
            saved = self._save(self._settings_with(approvals=False))
            self._audit_operator('imessage:approvals-disable', 'operator-settings', 'completed' if saved else 'failed')
        return self.status()

    # --- enablement ------------------------------------------------------------

    @_serialized
    async def enable(self):
        await self._refresh_model()
        if self._unreadable:
            self._error = ERR_UNREADABLE
            return self.status()
        paired = self._paired()
        if paired is None:
            self._error = ERR_NOT_PAIRED
            return self.status()
        if not self._agent_active(paired['agent_id']):
            self._error = ERR_REVOKED
            return self.status()
        if not self._model_ready():
            self._error = ERR_MODEL
            return self.status()
        if not self._helpers_ready():
            self._error = ERR_UNAVAILABLE
            return self.status()
        try:
            identity = self._database_identity()
            if not self._ledger.is_database_current(str(paired['chat_id']), identity):
                self._error = ERR_STALE
                return self.status()
            # Only messages after this moment are answered; anything sent while disabled is skipped.
            self._ledger.baseline(str(paired['chat_id']), identity, self._clock())
        except MessagesBridgeError:
            self._error = ERR_UNAVAILABLE
            return self.status()
        except MessageLedgerError:
            self._error = ERR_UNAVAILABLE
            return self.status()
        if not self._save(self._settings_with(enabled=True, halted=None)):
            return self.status()
        self._error = None
        await self._stop_loop()
        self._start_loop(paired)
        return self.status()

    @_serialized
    async def disable(self):
        await self._stop_loop()
        await self._cancel_pairing()
        if not self._unreadable and self._settings['enabled']:
            self._save(self._settings_with(enabled=False))
        return self.status()

    @_serialized
    async def start(self):
        """Resume the command loop if it was enabled before. Never enables anything."""
        if self._loop_running():
            return
        await self._refresh_model()
        if not self._can_run():
            return
        self._start_loop(self._paired())

    @_serialized
    async def stop(self):
        await self._stop_loop()
        await self._cancel_pairing()

    def _start_loop(self, paired):
        self._loop_task = asyncio.create_task(self._run_loop(paired['chat_id'], paired['agent_id']))

    async def _stop_loop(self):
        self._conversation.clear()
        task, self._loop_task = self._loop_task, None
        if task is not None:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    def _halt(self, code):
        self._conversation.clear()
        if not self._unreadable:
            self._save(self._settings_with(enabled=False, halted=code))
        self._error = code

    # --- command loop ----------------------------------------------------------

    async def _run_loop(self, chat_id, agent_id):
        failures = 0
        self._cursor = 0
        while True:
            bridge = None
            connected_at = None
            try:
                bridge = self._bridge_factory(chat_id)
                await bridge.start()
                identity = bridge.database_identity()
                if not self._ledger.is_database_current(str(chat_id), identity):
                    raise _Halt(ERR_STALE)
                await bridge.subscribe(since_rowid=self._cursor)
                self._error = None
                connected_at = self._clock()
                await self._serve(bridge, chat_id, agent_id, identity)
                # The stream ended without being cancelled: treat it as a failure and restart.
                self._error = ERR_LOOP
            except _Halt as halt:
                self._halt(halt.code)
                return
            except _Restart:
                self._error = ERR_LOOP
            except Exception:
                self._error = ERR_LOOP
            finally:
                if bridge is not None:
                    await bridge.close()
            failures = _next_failures(failures, connected_at, self._clock())
            delay = min(RETRY_BASE_SECONDS * 2 ** min(failures - 1, 8), RETRY_CAP_SECONDS)
            await asyncio.sleep(delay)

    async def _serve(self, bridge, chat_id, agent_id, identity):
        """Run the reader, the sequential command worker, and the approval announcer until one ends the connection.

        Commands queue behind the worker so a command waiting on an approval cannot block the reader, which must
        keep reading so an 'approve' reply can arrive.
        """
        jobs = asyncio.Queue()
        tasks = {
            asyncio.create_task(self._read(bridge, chat_id, agent_id, identity, jobs)),
            asyncio.create_task(self._work(bridge, agent_id, jobs)),
            asyncio.create_task(self._announce(bridge)),
        }
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            # Commands claimed but never started are skipped, not replayed, so a torn-down loop cannot answer late.
            while not jobs.empty():
                self._ledger.mark_result(jobs.get_nowait(), 'skipped')

    async def _read(self, bridge, chat_id, agent_id, identity, jobs):
        async for event in bridge.messages():
            self._cursor = max(self._cursor, event['rowid'])
            command = _parse_command(event, chat_id)
            if command is not None:
                if not self._agent_active(agent_id):
                    raise _Halt(ERR_REVOKED)
                message_id, rowid, date, request = command
                if self._ledger.claim(str(chat_id), message_id, date, rowid, database_id=identity):
                    jobs.put_nowait((message_id, request))
                continue
            approval = _parse_approval(event, chat_id)
            if approval is not None and self._approvals_on():
                if not self._agent_active(agent_id):
                    raise _Halt(ERR_REVOKED)
                await self._approval_reply(bridge, chat_id, identity, approval)

    async def _work(self, bridge, agent_id, jobs):
        while True:
            message_id, request = await jobs.get()
            await self._command(bridge, agent_id, message_id, request)

    async def _command(self, bridge, agent_id, message_id, request):
        verdict = self._limiter.admit(self._clock())
        if verdict != 'accept':
            if verdict == 'notify':
                await self._notify(bridge, RATE_NOTICE)
            self._ledger.mark_result(message_id, 'skipped')
            return
        self._ledger.mark_attempted(message_id)
        self._style.observe(request)
        history = self._conversation.text(self._clock())
        reply = await self._agent.reply(agent_id, lambda: self._agent_active(agent_id), request, history,
                                        self._style.notes())
        try:
            await bridge.send_text(reply)
        except MessagesBridgeError as error:
            # Never resend automatically: the send may or may not have reached the chat.
            self._ledger.mark_result(message_id, 'failed')
            if error.code in RESTART_CODES:
                # The helper's send lane may now be blocked; a fresh helper resumes after this message.
                raise _Restart()
            return
        self._ledger.mark_result(message_id, 'sent')
        self._conversation.add(request, reply, self._clock())

    async def _announce(self, bridge):
        while True:
            if self._approvals_on():
                await self._announce_pending(bridge)
            await asyncio.sleep(APPROVAL_POLL_SECONDS)

    async def _announce_pending(self, bridge):
        """Send one text for the head pending request. Each request is attempted once and never retried."""
        pending = self._approvals.get_pending()
        if pending is None or pending.agent == 'operator' or pending.request_id in self._attempted_requests:
            return
        self._attempted_requests.add(pending.request_id)
        text, approvable = announcement(pending, _clean(pending.agent))
        try:
            await bridge.send_text(text)
        except MessagesBridgeError as error:
            # Like the reply paths: a blocked or uncertain send restarts the helper. Never resend the announcement.
            if error.code in RESTART_CODES:
                raise _Restart()
            return
        if approvable:
            self._delivered_requests.add(pending.request_id)

    async def _approval_reply(self, bridge, chat_id, identity, approval):
        message_id, rowid, date, verb, code = approval
        if not self._ledger.claim(str(chat_id), message_id, date, rowid, database_id=identity):
            return
        verdict = self._limiter.admit(self._clock())
        if verdict != 'accept':
            if verdict == 'notify':
                await self._notify(bridge, RATE_NOTICE)
            self._ledger.mark_result(message_id, 'skipped')
            return
        self._ledger.mark_attempted(message_id)
        pending = self._approvals.get_pending()
        matched = (pending is not None and pending.request_id in self._delivered_requests
                   and hmac.compare_digest(pending.approval_code.lower(), code))
        if not matched:
            reply = NO_MATCH_REPLY
        else:
            approved = verb == 'approve'
            self._approvals.resolve(pending, approved)
            self._audit_operator(pending.credential, 'imessage-approval', 'approved' if approved else 'denied')
            reply = APPROVED_REPLY if approved else DENIED_REPLY
        try:
            await bridge.send_text(reply)
        except MessagesBridgeError as error:
            self._ledger.mark_result(message_id, 'failed')
            if error.code in RESTART_CODES:
                raise _Restart()
            return
        self._ledger.mark_result(message_id, 'sent')

    async def _notify(self, bridge, text):
        try:
            await bridge.send_text(text)
        except MessagesBridgeError:
            pass
