"""Narrow, allowlisted async wrapper around the imsg JSON-RPC helper.

The bridge is bound to one paired self-chat. It spawns `<helper> rpc --db <db>`
without a shell, speaks newline-delimited JSON-RPC over stdin/stdout, and only
ever writes methods from the instance's allowlist. Raw RPC is never exposed.

`MessagesBridge` is the normal paired instance: it can read and send only in the
verified paired chat. `PairingBridge` is the separate discovery mode used while
pairing: it can list recent chats and read recent history, but cannot send or
subscribe.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import itertools
import json
import os
from pathlib import Path
import re
import stat
import uuid

from broker.helper_env import minimal_helper_env

MAX_LINE_BYTES = 1024 * 1024
MAX_REQUEST_BYTES = 64 * 1024
MAX_TEXT_CHARS = 4000
MAX_SENDER_CHARS = 320
MAX_GUID_CHARS = 256
MAX_EVENTS = 256
MAX_RECOVERY_PAGES = 5
RECOVERY_PAGE_LIMIT = 100
MAX_RECOVERIES = 20
MAX_DISCOVERY_LIMIT = 50
DEFAULT_REQUEST_TIMEOUT = 10.0
DEFAULT_SEND_TIMEOUT = 30.0
DEFAULT_SHUTDOWN_TIMEOUT = 2.0
PROTOCOL_VERSION = 1
READ_CHUNK = 65536
RPC_SEND_UNCERTAIN = -32001
RPC_SEND_LANE_BLOCKED = -32004
ALLOWED_METHODS = frozenset({'initialize', 'chats.get', 'watch.subscribe', 'messages.after', 'send'})
PAIRING_METHODS = frozenset({'initialize', 'chats.list', 'chats.get', 'messages.history'})

ERRORS = {
    'unsafe_helper': 'The iMessage helper is missing or is not safely installed.',
    'startup_failed': 'The iMessage helper could not be started.',
    'not_running': 'The iMessage bridge is not running.',
    'method_not_allowed': 'That iMessage operation is not allowed.',
    'chat_not_paired': 'That chat is not the paired chat.',
    'chat_mismatch': 'The paired iMessage chat could not be verified as your self-chat.',
    'invalid_input': 'The iMessage request is invalid.',
    'timeout': 'The iMessage helper did not respond in time.',
    'send_uncertain': 'The message may or may not have been sent. It will not be retried automatically.',
    'send_failed': 'The iMessage helper could not send the message.',
    'send_blocked': 'An earlier iMessage send is still unresolved, so this message was not sent. It will not be retried automatically.',
    'rpc_error': 'The iMessage helper returned an error.',
    'protocol_error': 'The iMessage helper returned an unexpected response.',
    'bridge_closed': 'The iMessage helper stopped.',
    'database_unavailable': 'The Messages database is not available.',
    'overflow': 'Incoming iMessage events overflowed and could not be recovered. Stop and recover before continuing.',
}

_END = object()
_E164ISH = re.compile(r'[^0-9+]')


class _Recover:
    """Queued marker: resume the paired stream after this cursor, in arrival order."""

    __slots__ = ('cursor',)

    def __init__(self, cursor):
        self.cursor = cursor


class MessagesBridgeError(Exception):
    def __init__(self, code, rpc_code=None):
        self.code = code
        self.rpc_code = rpc_code
        super().__init__(ERRORS[code])


def _directory_info(path):
    return os.stat(path)


def verify_helper(path):
    """Raise unsafe_helper unless the helper and every directory above it is private to the user or root."""
    try:
        info = path.lstat()
    except OSError:
        raise MessagesBridgeError('unsafe_helper')
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o022 or not info.st_mode & 0o100):
        raise MessagesBridgeError('unsafe_helper')
    home = Path.home()
    current = path.parent
    while True:
        try:
            directory = _directory_info(current)
        except OSError:
            raise MessagesBridgeError('unsafe_helper')
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid not in (os.getuid(), 0)
                or directory.st_mode & 0o022):
            raise MessagesBridgeError('unsafe_helper')
        if current == home or current.parent == current:
            return
        current = current.parent


def _is_plain_int(value):
    return type(value) is int


def _valid_guid(value):
    return (isinstance(value, str) and 0 < len(value) <= MAX_GUID_CHARS
            and not any(ord(ch) < 32 or ord(ch) == 127 for ch in value))


def _valid_text(value):
    return isinstance(value, str) and 0 < len(value) <= MAX_TEXT_CHARS and '\x00' not in value


def _parse_date(value):
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed


def _handle_key(value):
    """Canonical form of an Apple ID or phone handle, or None when it is not usable."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if len(text) > 2 and text[0].isalpha() and text[1] == ':':
        text = text[2:]  # Messages stores account logins as "E:<email>" or "P:<phone>".
    if '@' in text:
        return text.lower()
    digits = _E164ISH.sub('', text)
    return digits or None


_ONE_TO_ONE_GUID_PREFIXES = ('iMessage;-;', 'any;-;')


def is_self_chat(chat):
    """True only for a 1:1 iMessage chat whose single participant is one of your own handles.

    Checks: is_group is exactly False; service is exactly 'iMessage'; the GUID is a
    one-to-one GUID ('iMessage;-;...' or, on newer macOS, 'any;-;...'); participants is
    exactly one handle; and that participant equals either the account login or the
    handle you last sent from in this chat (in a chat with someone else, that handle is
    yours and the participant is theirs). Anything missing or ambiguous is refused.
    """
    if not isinstance(chat, dict) or chat.get('is_group') is not False:
        return False
    if chat.get('service') != 'iMessage':
        return False
    guid = chat.get('guid')
    if not isinstance(guid, str) or not guid.startswith(_ONE_TO_ONE_GUID_PREFIXES):
        return False
    participants = chat.get('participants')
    if not isinstance(participants, list) or len(participants) != 1:
        return False
    other = _handle_key(participants[0])
    mine = {_handle_key(chat.get('account_login')), _handle_key(chat.get('last_addressed_handle'))}
    return other is not None and other in mine


def _normalize_chat(value, chat_id):
    if not isinstance(value, dict) or type(value.get('id')) is not int or value.get('id') != chat_id:
        return None
    guid, service, is_group = value.get('guid'), value.get('service'), value.get('is_group')
    participants = value.get('participants', [])
    if not _valid_guid(guid) or not isinstance(service, str) or type(is_group) is not bool:
        return None
    if not isinstance(participants, list) or not all(
            isinstance(p, str) and 0 < len(p) <= MAX_SENDER_CHARS for p in participants):
        return None
    account, addressed = value.get('account_login'), value.get('last_addressed_handle')
    if not isinstance(account, str) or len(account) > MAX_SENDER_CHARS:
        account = None
    if not isinstance(addressed, str) or len(addressed) > MAX_SENDER_CHARS:
        addressed = None
    return {'id': chat_id, 'guid': guid, 'service': service, 'is_group': is_group,
            'participants': participants, 'account_login': account,
            'last_addressed_handle': addressed}


def _normalize_message(message, paired_chat_id):
    """Return a safe incoming-message dict, or None for anything malformed or off-chat."""
    if not isinstance(message, dict):
        return None
    rowid, chat_id = message.get('id'), message.get('chat_id')
    guid, chat_guid = message.get('guid'), message.get('chat_guid')
    text = message.get('text', '')
    sender = message.get('sender', '')
    is_from_me, is_group = message.get('is_from_me'), message.get('is_group')
    if not _is_plain_int(rowid) or rowid <= 0:
        return None
    if not _is_plain_int(chat_id) or chat_id != paired_chat_id:
        return None
    if not isinstance(guid, str) or not 0 < len(guid) <= MAX_GUID_CHARS:
        return None
    if not isinstance(chat_guid, str) or len(chat_guid) > MAX_GUID_CHARS:
        return None
    if text is None:
        text = ''
    if sender is None:
        sender = ''
    if not isinstance(text, str) or not isinstance(sender, str):
        return None
    if type(is_from_me) is not bool or type(is_group) is not bool:
        return None
    date = _parse_date(message.get('created_at'))
    if date is None:
        return None
    return {
        'chat_id': chat_id,
        'chat_guid': chat_guid,
        'guid': guid,
        'rowid': rowid,
        'date': date,
        'text': text[:MAX_TEXT_CHARS],
        'is_from_me': is_from_me,
        'is_group': is_group,
        'sender': sender[:MAX_SENDER_CHARS],
    }


def _normalize_event(params, paired_chat_id):
    if not isinstance(params, dict) or not _is_plain_int(params.get('subscription')):
        return None
    return _normalize_message(params.get('message'), paired_chat_id)


class MessagesBridge:
    ALLOWED = ALLOWED_METHODS

    def __init__(self, helper_path, db_path=None, *, paired_chat_id,
                 request_timeout=DEFAULT_REQUEST_TIMEOUT,
                 send_timeout=DEFAULT_SEND_TIMEOUT,
                 shutdown_timeout=DEFAULT_SHUTDOWN_TIMEOUT,
                 max_events=MAX_EVENTS):
        self._paired_chat_id = self._check_paired(paired_chat_id)
        self.helper_path = Path(helper_path).expanduser().absolute()
        if db_path is None:
            self.db_path = Path.home() / 'Library' / 'Messages' / 'chat.db'
        else:
            self.db_path = Path(db_path).expanduser().absolute()
        self._request_timeout = request_timeout
        self._send_timeout = send_timeout
        self._shutdown_timeout = shutdown_timeout
        self._max_events = max_events
        self._proc = None
        self._reader = None
        self._pending = {}
        self._ids = itertools.count(1)
        self._events = None
        self._stopped = False
        self._error = None
        self._subscription = None
        self._chat_guid = None

    @classmethod
    def for_pairing(cls, helper_path, db_path=None, **kwargs):
        """Pairing-only discovery instance. It has no paired chat and cannot send."""
        return PairingBridge(helper_path, db_path, **kwargs)

    def _check_paired(self, value):
        if not _is_plain_int(value) or value <= 0:
            raise MessagesBridgeError('invalid_input')
        return value

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *exc_info):
        await self.close()

    async def start(self):
        if self._proc is not None:
            return
        verify_helper(self.helper_path)
        self._events = asyncio.Queue(maxsize=self._max_events)
        self._stopped = False
        self._error = None
        try:
            self._proc = await asyncio.create_subprocess_exec(
                str(self.helper_path), 'rpc', '--db', str(self.db_path),
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL, env=minimal_helper_env())
        except OSError:
            raise MessagesBridgeError('startup_failed')
        self._reader = asyncio.create_task(self._read_loop())
        try:
            result = await self._request('initialize', {'protocol_version': PROTOCOL_VERSION})
            if not isinstance(result, dict):
                raise MessagesBridgeError('protocol_error')
            await self._verify_paired_chat()
        except BaseException:
            await self.close()
            raise

    async def _verify_paired_chat(self):
        chat = _normalize_chat(await self._request('chats.get', {'chat_id': self._paired_chat_id}),
                               self._paired_chat_id)
        if chat is None or not is_self_chat(chat):
            raise MessagesBridgeError('chat_mismatch')
        self._chat_guid = chat['guid']

    async def close(self):
        proc = self._proc
        if proc is None:
            return
        self._stop(None)
        if proc.stdin is not None:
            try:
                proc.stdin.close()
            except OSError:
                pass
        try:
            await asyncio.wait_for(proc.wait(), self._shutdown_timeout)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()
        if self._reader is not None:
            self._reader.cancel()
            await asyncio.gather(self._reader, return_exceptions=True)
        self._proc = None
        self._reader = None
        self._subscription = None
        self._chat_guid = None

    def database_identity(self):
        """Stable file identity (device:inode) of the Messages database. Contents are never read."""
        try:
            info = os.stat(self.db_path)
        except OSError:
            raise MessagesBridgeError('database_unavailable')
        if not stat.S_ISREG(info.st_mode):
            raise MessagesBridgeError('database_unavailable')
        return f'{info.st_dev}:{info.st_ino}'

    async def get_chat(self, chat_id):
        self._require_paired(chat_id)
        chat = _normalize_chat(await self._request('chats.get', {'chat_id': chat_id}), chat_id)
        if chat is None:
            raise MessagesBridgeError('protocol_error')
        return chat

    async def subscribe(self, since_rowid=0):
        if not _is_plain_int(since_rowid) or since_rowid < 0:
            raise MessagesBridgeError('invalid_input')
        result = await self._request('watch.subscribe', {
            'chat_id': self._paired_chat_id, 'since_rowid': since_rowid,
            'attachments': False, 'include_reactions': False,
            'debounce_ms': 500, 'buffer_limit': 64})
        subscription = result.get('subscription') if isinstance(result, dict) else None
        if not _is_plain_int(subscription):
            raise MessagesBridgeError('protocol_error')
        return subscription

    async def send_text(self, text):
        """Send text to the verified paired self-chat. The chat GUID is never caller-supplied."""
        if self._chat_guid is None:
            raise MessagesBridgeError('not_running')
        if not _valid_text(text):
            raise MessagesBridgeError('invalid_input')
        try:
            result = await self._request('send', {
                'chat_guid': self._chat_guid, 'text': text, 'service': 'imessage',
                'transport': 'applescript', 'allow_sms_fallback': False}, timeout=self._send_timeout)
        except MessagesBridgeError as error:
            if error.code == 'rpc_error' and error.rpc_code == RPC_SEND_LANE_BLOCKED:
                raise MessagesBridgeError('send_blocked')
            if error.code == 'rpc_error' and error.rpc_code != RPC_SEND_UNCERTAIN:
                raise MessagesBridgeError('send_failed')
            if error.code in ('rpc_error', 'timeout', 'bridge_closed'):
                raise MessagesBridgeError('send_uncertain')
            raise
        if not isinstance(result, dict) or result.get('ok') is not True:
            raise MessagesBridgeError('send_uncertain')
        return True

    async def messages(self):
        """Yield normalized incoming messages for the paired chat until closed.

        A server-side watch.overflow is recovered here with bounded messages.after
        pages followed by a fresh subscription at the authoritative cursor. Client-side
        queue overflow is not recoverable and fails closed.
        """
        if self._events is None:
            raise MessagesBridgeError('not_running')
        recoveries = 0
        while True:
            item = await self._events.get()
            if isinstance(item, _Recover):
                if self._stopped:
                    continue  # Closed while queued: the _END marker follows and ends the stream.
                recoveries += 1
                if recoveries > MAX_RECOVERIES:
                    raise MessagesBridgeError('overflow')
                async for event in self._recover(item.cursor):
                    yield event
                continue
            if item is _END:
                self._events.put_nowait(_END)
                if self._error is not None:
                    raise MessagesBridgeError(self._error.code)
                return
            yield item

    async def _recover(self, cursor):
        if not _is_plain_int(cursor) or cursor <= 0:
            raise MessagesBridgeError('overflow')
        since = cursor
        for _ in range(MAX_RECOVERY_PAGES):
            result = await self._request('messages.after', {
                'chat_id': self._paired_chat_id, 'since_rowid': since,
                'limit': RECOVERY_PAGE_LIMIT, 'attachments': False,
                'convert_attachments': False, 'include_reactions': False})
            if not isinstance(result, dict):
                raise MessagesBridgeError('protocol_error')
            messages, next_rowid, has_more = result.get('messages'), result.get('next_rowid'), result.get('has_more')
            if not isinstance(messages, list) or not _is_plain_int(next_rowid) or type(has_more) is not bool:
                raise MessagesBridgeError('protocol_error')
            if next_rowid < since:
                raise MessagesBridgeError('protocol_error')
            for message in messages[:RECOVERY_PAGE_LIMIT]:
                event = _normalize_message(message, self._paired_chat_id)
                if event is not None:
                    yield event
            since = next_rowid
            if not has_more:
                if since <= 0:
                    raise MessagesBridgeError('overflow')
                await self.subscribe(since)
                return
        raise MessagesBridgeError('overflow')

    def _require_paired(self, chat_id):
        if not _is_plain_int(chat_id) or chat_id != self._paired_chat_id:
            raise MessagesBridgeError('chat_not_paired')

    async def _request(self, method, params, timeout=None):
        if method not in self.ALLOWED:
            raise MessagesBridgeError('method_not_allowed')
        proc = self._proc
        if proc is None or proc.stdin is None:
            raise MessagesBridgeError('not_running')
        if self._stopped:
            raise MessagesBridgeError('bridge_closed')
        request_id = f'{method}-{next(self._ids)}-{uuid.uuid4().hex}'
        payload = json.dumps({'jsonrpc': '2.0', 'id': request_id, 'method': method,
                              'params': params}, separators=(',', ':')).encode()
        if len(payload) + 1 > MAX_REQUEST_BYTES:
            raise MessagesBridgeError('invalid_input')
        future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = (future, method)
        try:
            return await asyncio.wait_for(self._write_and_wait(proc, payload + b'\n', future),
                                          timeout or self._request_timeout)
        except asyncio.TimeoutError:
            raise MessagesBridgeError('timeout')
        finally:
            self._pending.pop(request_id, None)

    async def _write_and_wait(self, proc, data, future):
        try:
            proc.stdin.write(data)
            await proc.stdin.drain()
        except OSError:
            raise MessagesBridgeError('bridge_closed')
        return await future

    async def _read_loop(self):
        reader = self._proc.stdout
        buffer = bytearray()
        discarding = False
        try:
            while True:
                chunk = await reader.read(READ_CHUNK)
                if not chunk:
                    self._stop('bridge_closed')
                    return
                buffer.extend(chunk)
                while True:
                    index = buffer.find(b'\n')
                    if index == -1:
                        if discarding or len(buffer) > MAX_LINE_BYTES:
                            discarding = True
                            buffer.clear()
                        break
                    line = bytes(buffer[:index])
                    del buffer[:index + 1]
                    if discarding:
                        discarding = False
                        continue
                    if len(line) > MAX_LINE_BYTES:
                        continue
                    self._dispatch(line)
                    if self._stopped:
                        return
        except OSError:
            self._stop('bridge_closed')

    def _dispatch(self, line):
        try:
            message = json.loads(line)
        except ValueError:
            return
        if not isinstance(message, dict):
            return
        if 'method' in message and 'id' not in message:
            self._on_notification(message)
            return
        request_id = message.get('id')
        entry = self._pending.get(request_id) if isinstance(request_id, str) else None
        if entry is None:
            return
        future, method = entry
        if future.done():
            return
        if 'error' in message:
            error = message['error']
            rpc_code = error.get('code') if isinstance(error, dict) else None
            future.set_exception(MessagesBridgeError(
                'rpc_error', rpc_code=rpc_code if _is_plain_int(rpc_code) else None))
        elif 'result' in message:
            result = message['result']
            if method == 'watch.subscribe' and isinstance(result, dict) and _is_plain_int(result.get('subscription')):
                # Set before resolving the future: notifications may be read before the awaiting task resumes.
                self._subscription = result['subscription']
            future.set_result(result)

    def _on_notification(self, message):
        method, params = message.get('method'), message.get('params')
        if self._stopped or self._subscription is None or not isinstance(params, dict):
            return
        if params.get('subscription') != self._subscription:
            return
        if method == 'message':
            event = _normalize_event(params, self._paired_chat_id)
            if event is None:
                return
            try:
                self._events.put_nowait(event)
            except asyncio.QueueFull:
                self._stop('overflow')
        elif method == 'watch.overflow':
            # The overflow is terminal for this subscription: stop accepting its events. Anything it
            # would have carried is recovered from the database by messages.after before resubscribing.
            self._subscription = None
            resume = params.get('resume_after_rowid')
            if not _is_plain_int(resume) or resume <= 0:
                self._stop('overflow')
                return
            try:
                self._events.put_nowait(_Recover(resume))
            except asyncio.QueueFull:
                self._stop('overflow')

    def _stop(self, code):
        """Fail in-flight work and end the event stream. Only the first call counts."""
        if self._stopped or self._events is None:
            return
        self._stopped = True
        if code is not None:
            self._error = MessagesBridgeError(code)
        for future, _method in self._pending.values():
            if not future.done():
                future.set_exception(MessagesBridgeError(code or 'bridge_closed'))
        self._pending.clear()
        if code == 'overflow':
            while not self._events.empty():
                self._events.get_nowait()
        while self._events.full():
            self._events.get_nowait()
        self._events.put_nowait(_END)


class PairingBridge(MessagesBridge):
    """Discovery-only instance used to find the self-chat during pairing.

    It is bound to no chat, cannot send, cannot subscribe, and never sees the
    paired chat's stream. Only chats.list, chats.get, and messages.history are allowed.
    """

    ALLOWED = PAIRING_METHODS

    def __init__(self, helper_path, db_path=None, **kwargs):
        super().__init__(helper_path, db_path, paired_chat_id=None, **kwargs)

    def _check_paired(self, value):
        if value is not None:
            raise MessagesBridgeError('invalid_input')
        return None

    async def _verify_paired_chat(self):
        return None

    def _require_paired(self, chat_id):
        if not _is_plain_int(chat_id) or chat_id <= 0:
            raise MessagesBridgeError('chat_not_paired')

    async def list_chats(self, limit=25):
        if not _is_plain_int(limit) or not 1 <= limit <= MAX_DISCOVERY_LIMIT:
            raise MessagesBridgeError('invalid_input')
        result = await self._request('chats.list', {'limit': limit})
        chats = result.get('chats') if isinstance(result, dict) else None
        if not isinstance(chats, list):
            raise MessagesBridgeError('protocol_error')
        return [c['id'] for c in chats if isinstance(c, dict) and _is_plain_int(c.get('id')) and c['id'] > 0][:limit]

    async def history(self, chat_id, limit=10):
        if not _is_plain_int(chat_id) or chat_id <= 0:
            raise MessagesBridgeError('chat_not_paired')
        if not _is_plain_int(limit) or not 1 <= limit <= MAX_DISCOVERY_LIMIT:
            raise MessagesBridgeError('invalid_input')
        result = await self._request('messages.history', {'chat_id': chat_id, 'limit': limit})
        messages = result.get('messages') if isinstance(result, dict) else None
        if not isinstance(messages, list):
            raise MessagesBridgeError('protocol_error')
        found = []
        for message in messages[:limit]:
            if not isinstance(message, dict) or not _is_plain_int(message.get('id')) or message['id'] <= 0:
                continue
            text = message.get('text')
            text = '' if text is None else text
            is_from_me = message.get('is_from_me')
            date = _parse_date(message.get('created_at'))
            if not isinstance(text, str) or type(is_from_me) is not bool or date is None:
                continue
            found.append({'rowid': message['id'], 'chat_id': chat_id, 'text': text[:MAX_TEXT_CHARS],
                          'is_from_me': is_from_me, 'date': date})
        return found
