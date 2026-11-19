"""Operator-owned lifecycle for broker integrations."""
from __future__ import annotations

import asyncio
import json
from typing import Any

from broker.integrations import calendar as calendar_provider
from broker.integrations import gmail as gmail_provider
from broker.integrations.calendar import Calendar, CalendarError
from broker.integrations.gmail import Gmail, GmailError, INTERNAL_PREFIX, TOKEN_NAME


ACCOUNT_NAME = INTERNAL_PREFIX + 'gmail-account'


class _CaptureStore:
    """Collect credentials produced by OAuth without touching the live store."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def store(self, name: str, value: str) -> None:
        self.values[name] = value


class GoogleConnection:
    """Manage one Google provider's encrypted OAuth credentials and reconnect job."""

    service = 'gmail'
    label = 'Gmail'
    token_name = TOKEN_NAME
    account_name = ACCOUNT_NAME
    provider_error: type[Exception] = GmailError

    def __init__(self, broker, provider, client_file: str):
        self.broker = broker
        self.provider = provider
        self.client_file = client_file
        self._generation = 0
        self._job_generation = 0
        self._disconnected = False
        self._task: asyncio.Task | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._job: dict[str, Any] = {'active': False, 'state': 'idle'}
        self._committed_job_generation: int | None = None
        self._committed_account: dict | None = None

    @property
    def gmail(self):
        return self.provider

    def _connect(self, client_file: str, capture: _CaptureStore) -> str:
        # Resolved at call time so tests can replace the provider's OAuth flow.
        return gmail_provider.connect(client_file, capture)

    def _cached_account(self) -> dict | None:
        try:
            value = json.loads(self.broker.store.retrieve(self.account_name))
        except (KeyError, ValueError, TypeError):
            return None
        email = value.get('email') if isinstance(value, dict) else None
        return {'email': email} if isinstance(email, str) and email else None

    def info(self) -> dict:
        # Keep profile metadata and credential removal ordered together.
        with self.provider._lock:
            return self._info_locked()

    def _info_locked(self) -> dict:
        names = self.broker.store.list_names()
        if self.token_name not in names or self._disconnected:
            return {'service': self.service, 'status': 'disconnected', 'account': None,
                    'reconnecting': bool(self._job['active'])}
        try:
            account = self.provider.call('account')
            # Keep account metadata encrypted in the broker's credential store.
            self.broker.store.store(self.account_name, json.dumps(account, separators=(',', ':')))
            status = 'connected'
            error = None
        except self.provider_error as exc:
            account = self._cached_account()
            message = str(exc)
            if 'authorization' in message.lower() or 'reconnect' in message.lower():
                status = 'needs_reconnect'
                error = f'Google authorization needs renewal. Reconnect {self.label}.'
            elif 'not connected' in message.lower():
                status = 'disconnected'
                error = None
            else:
                status = 'unavailable'
                error = f'{self.label} account status could not be checked.'
        result = {'service': self.service, 'status': status, 'account': account,
                  'reconnecting': bool(self._job['active'])}
        if error:
            result['error'] = error
        return result

    def disconnect(self) -> None:
        """Delete local OAuth and account metadata; never contact Google's revoke API."""
        with self.provider._lock:
            self._generation += 1
            self._disconnected = True
            self.provider._suspended = True
            names = set(self.broker.store.list_names())
            remove = tuple(name for name in (self.token_name, self.account_name) if name in names)
            if remove:
                self.broker.store.update({}, delete=remove)
            self.provider._credentials = None
            self.provider._service = None
        self._cancel_job()
        self._job_generation += 1
        self._job = {'active': False, 'state': 'failed', 'error': 'Reconnect was canceled.'}

    def _cancel_job(self) -> None:
        task, loop = self._task, self._loop
        if task is not None and not task.done() and loop is not None:
            loop.call_soon_threadsafe(task.cancel)

    def begin_reconnect(self) -> dict:
        if self._job['active']:
            return self.reconnect_status()
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            raise RuntimeError('begin_reconnect must be called from an async event loop') from None
        # This method runs on the event loop. The dashboard serializes start vs
        # disconnect, so reading the generation here never needs to wait on the
        # provider lock (which can be held during a network request).
        generation = self._generation
        self._disconnected = False
        self._job_generation += 1
        job_generation = self._job_generation
        self._loop = loop
        self._job = {'active': True, 'state': 'connecting'}
        self._task = loop.create_task(self._reconnect(generation, job_generation))
        return self.reconnect_status()

    def reconnect_status(self) -> dict:
        # Return a fresh JSON-safe view; OAuth payloads are never exposed here.
        return dict(self._job)

    async def _reconnect(self, generation: int, job_generation: int) -> None:
        capture = _CaptureStore()
        try:
            account_email = await asyncio.to_thread(self._connect, self.client_file, capture)
            if not isinstance(account_email, str) or not account_email:
                raise self.provider_error(f'{self.label} did not return an account address.')
            staged_token = capture.values.get(self.token_name)
            if not staged_token:
                raise self.provider_error(f'Google did not issue offline access; reconnect {self.label}.')

            # Suspend new calls while installing staged credentials. Advancing the
            # broker revision rejects approvals that were waiting across reconnect.
            prepared = await asyncio.to_thread(self._prepare_staged, generation)
            if not prepared:
                raise asyncio.CancelledError
            self.broker.invalidate_agent_requests()
            await asyncio.to_thread(self._commit_staged, generation, job_generation,
                                    staged_token, account_email)
            self.broker.invalidate_agent_requests()
            if job_generation == self._job_generation:
                self._job = {'active': False, 'state': 'completed',
                             'account': {'email': account_email}}
        except asyncio.CancelledError:
            if job_generation == self._job_generation:
                self._job = {'active': False, 'state': 'failed', 'error': 'Reconnect was canceled.'}
            raise
        except Exception:
            # OAuth and provider exception text can contain account or secret data.
            if job_generation == self._job_generation:
                self._job = {'active': False, 'state': 'failed',
                             'error': f'{self.label} reconnect failed. Try again.'}
            await asyncio.to_thread(self._restore_after_failure, generation, job_generation)
        finally:
            if self._task is asyncio.current_task():
                self._task = None

    def _commit_staged(self, generation: int, job_generation: int,
                       token_json: str, account_email: str) -> None:
        with self.provider._lock:
            if generation != self._generation or self._disconnected:
                raise RuntimeError('reconnect was canceled')
            staged = {
                self.token_name: token_json,
                self.account_name: json.dumps({'email': account_email}, separators=(',', ':')),
            }
            self.broker.store.update(staged)
            self.provider._credentials = None
            self.provider._service = None
            self._disconnected = False
            self.provider._suspended = False
            self._committed_job_generation = job_generation
            self._committed_account = {'email': account_email}

    def _prepare_staged(self, generation: int) -> bool:
        with self.provider._lock:
            if generation != self._generation or self._disconnected:
                return False
            self.provider._suspended = True
            return True

    def _restore_after_failure(self, generation: int, job_generation: int) -> None:
        with self.provider._lock:
            if (generation == self._generation and job_generation == self._job_generation
                    and not self._disconnected):
                self.provider._suspended = False

    async def close(self) -> None:
        task = self._task
        if task is not None and not task.done():
            # Fence commit under the same provider lock used by installation. If
            # commit owns the lock first, it finishes before close; otherwise its
            # generation check sees the fence and leaves staged data uninstalled.
            committed_job = await asyncio.to_thread(self._close_fence)
            committed = committed_job == self._job_generation
            self._job_generation += 1
            if committed:
                self._job = {'active': False, 'state': 'completed',
                             'account': self._committed_account}
            else:
                self._job = {'active': False, 'state': 'failed',
                             'error': 'Reconnect was canceled.'}
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    def _close_fence(self) -> int | None:
        with self.provider._lock:
            self._generation += 1
            return self._committed_job_generation


class GmailConnection(GoogleConnection):
    def __init__(self, broker, gmail: Gmail, client_file: str):
        super().__init__(broker, gmail, client_file)


class CalendarConnection(GoogleConnection):
    service = 'calendar'
    label = 'Google Calendar'
    token_name = calendar_provider.TOKEN_NAME
    account_name = calendar_provider.ACCOUNT_NAME
    provider_error = CalendarError

    def __init__(self, broker, calendar: Calendar, client_file: str):
        super().__init__(broker, calendar, client_file)

    def _connect(self, client_file: str, capture: _CaptureStore) -> str:
        return calendar_provider.connect(client_file, capture)
