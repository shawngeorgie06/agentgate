"""Owner-facing iMessage agent service: self-chat pairing, enablement, and the paired command loop.

The service owns the persisted pairing settings (config_dir/imessage.json, private 0600), runs at
most one pairing session and one command loop at a time, and fails closed: anything unreadable,
stale, revoked, or unavailable disables the loop rather than replying.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import functools
import json
import os
import secrets
import stat
import tempfile
from collections import deque
from pathlib import Path

from broker.apple_model import AppleModel
from broker.imessage_agent import ReadOnlyMessageAgent
from broker.imessage_bridge import MessagesBridge, MessagesBridgeError, is_self_chat, verify_helper
from broker.imessage_state import MessageLedger, MessageLedgerError

PAIRING_POLL_SECONDS = 2.0
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
SETTINGS_FILE = 'imessage.json'
SETTINGS_LIMIT = 4096
PAIRED_CONFIRMATION = 'AgentGate paired.'
RATE_NOTICE = 'AgentGate is handling recent requests. Please wait a moment before sending another.'
CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
COMMAND_PREFIX = '/agent '

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
RESTART_CODES = frozenset({'send_uncertain', 'send_blocked'})


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
        return {'available': False, 'enabled': False, 'paired': False, 'running': False, 'agent': None,
                'model': {'available': False, 'reason': 'iMessage is not available on this broker.'},
                'pairing': None, 'recent': [], 'error': self._error}

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


class AsyncAppleModel:
    """Async adapter over AppleModel. Blocking helper calls run in a worker thread."""

    def __init__(self, apple):
        self._apple = apple

    async def plan(self, prompt, history=''):
        return _data(await asyncio.to_thread(self._apple.plan, prompt, history))

    async def answer(self, prompt, context, history=''):
        data = _data(await asyncio.to_thread(self._apple.answer, prompt, context, history))
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
    if not isinstance(value, dict) or set(value) != {'enabled', 'paired'} or type(value['enabled']) is not bool:
        return False
    paired = value['paired']
    if paired is None:
        return value['enabled'] is False
    return (isinstance(paired, dict) and set(paired) == {'chat_id', 'agent_id'}
            and type(paired['chat_id']) is int and paired['chat_id'] > 0
            and isinstance(paired['agent_id'], str) and paired['agent_id'] != '')


def _read_settings(path: Path):
    """Return (settings, error). A missing file means unpaired; anything unsafe fails closed."""
    empty = {'enabled': False, 'paired': None}
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


def _parse_command(event, chat_id):
    """(message_id, rowid, date, request) for a paired-chat '/agent <request>' from me, else None."""
    if not isinstance(event, dict):
        return None
    if event.get('chat_id') != chat_id or event.get('is_group') is not False or event.get('is_from_me') is not True:
        return None
    text = event.get('text')
    message_id = event.get('guid')
    if not isinstance(text, str) or not isinstance(message_id, str) or not message_id:
        return None
    if not text.startswith(COMMAND_PREFIX):
        return None
    request = text[len(COMMAND_PREFIX):].strip()
    if not request:
        return None
    return message_id, event.get('rowid'), event.get('date'), request


class _Halt(Exception):
    """Stops the command loop and disables the agent with a safe reason code."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


class IMessageService:
    def __init__(self, config_dir, registry, gmail_tools, github_tools, *, imsg_path, model_helper_path,
                 audit=None, bridge_factory=None, model=None, clock=None):
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
        self._clock = clock or _utcnow
        self._limiter = _CommandLimiter()
        self._settings, self._error = _read_settings(self._settings_path)
        self._unreadable = self._error == ERR_UNREADABLE
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
            'agent': {'id': paired['agent_id'], 'name': paired['agent_id']} if paired else None,
            'model': self._model_availability(),
            'pairing': self._pairing_view(),
            'recent': self._recent(),
            'error': self._error,
        }

    def _paired(self):
        return None if self._unreadable else self._settings['paired']

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
            self._save({'enabled': False, 'paired': self._settings['paired']})
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
        if not self._save({'enabled': False, 'paired': {'chat_id': chat_id, 'agent_id': agent_id}}):
            return False
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
    async def unpair(self):
        await self._stop_loop()
        await self._cancel_pairing()
        if self._save({'enabled': False, 'paired': None}):
            self._error = None
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
        if not self._save({'enabled': True, 'paired': paired}):
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
            self._save({'enabled': False, 'paired': self._settings['paired']})
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
        task, self._loop_task = self._loop_task, None
        if task is not None:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    def _halt(self, code):
        if not self._unreadable:
            self._save({'enabled': False, 'paired': self._settings['paired']})
        self._error = code

    # --- command loop ----------------------------------------------------------

    async def _run_loop(self, chat_id, agent_id):
        failures = 0
        cursor = 0
        while True:
            bridge = None
            connected_at = None
            try:
                bridge = self._bridge_factory(chat_id)
                await bridge.start()
                identity = bridge.database_identity()
                if not self._ledger.is_database_current(str(chat_id), identity):
                    raise _Halt(ERR_STALE)
                await bridge.subscribe(since_rowid=cursor)
                self._error = None
                connected_at = self._clock()
                async for event in bridge.messages():
                    cursor = max(cursor, event['rowid'])
                    await self._handle(bridge, chat_id, agent_id, identity, event)
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

    async def _handle(self, bridge, chat_id, agent_id, identity, event):
        command = _parse_command(event, chat_id)
        if command is None:
            return
        if not self._agent_active(agent_id):
            raise _Halt(ERR_REVOKED)
        message_id, rowid, date, request = command
        if not self._ledger.claim(str(chat_id), message_id, date, rowid, database_id=identity):
            return
        verdict = self._limiter.admit(self._clock())
        if verdict != 'accept':
            if verdict == 'notify':
                await self._notify(bridge, RATE_NOTICE)
            self._ledger.mark_result(message_id, 'skipped')
            return
        self._ledger.mark_attempted(message_id)
        reply = await self._agent.reply(agent_id, lambda: self._agent_active(agent_id), request)
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

    async def _notify(self, bridge, text):
        try:
            await bridge.send_text(text)
        except MessagesBridgeError:
            pass
