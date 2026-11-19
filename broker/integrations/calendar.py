"""Single-account Google Calendar access with encrypted OAuth credentials."""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
import threading
from typing import Callable
from urllib.parse import quote
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import httplib2
import requests
from google.auth.exceptions import RefreshError, TransportError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_httplib2 import AuthorizedHttp
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from broker.credential_store import CredentialStore

INTERNAL_PREFIX = '__agentgate:'
TOKEN_NAME = INTERNAL_PREFIX + 'calendar-oauth'
ACCOUNT_NAME = INTERNAL_PREFIX + 'calendar-account'
SCOPES = [
    'https://www.googleapis.com/auth/calendar.readonly',
    'https://www.googleapis.com/auth/calendar.events',
]
TOKEN_URI = 'https://oauth2.googleapis.com/token'
API_BASE = 'https://www.googleapis.com/calendar/v3'
NOT_CONNECTED = 'Google Calendar is not connected. Connect it in the AgentGate app.'

_MAX_EVENT_RANGE = dt.timedelta(days=366)
_MAX_FREEBUSY_RANGE = dt.timedelta(days=62)
_MAX_EVENT_LENGTH = dt.timedelta(days=31)
_DATE = re.compile(r'\d{4}-\d{2}-\d{2}')
_CONTROL = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')


class CalendarError(Exception):
    """A safe error message that can be returned to an agent."""

    @property
    def safe_message(self):
        return str(self)


def connect(client_file: str, store: CredentialStore) -> str:
    # Installed-app flow validates OAuth state and uses PKCE on a loopback callback.
    flow = InstalledAppFlow.from_client_secrets_file(
        client_file, SCOPES, autogenerate_code_verifier=True
    )
    credentials = flow.run_local_server(
        host='127.0.0.1', port=0, timeout_seconds=180,
        access_type='offline', prompt='consent',
        authorization_prompt_message='Opening Google sign-in in your browser.',
    )
    if not credentials.refresh_token:
        raise CalendarError('Google did not issue offline access; reconnect Google Calendar.')
    granted = credentials.granted_scopes
    if granted is not None and not set(SCOPES).issubset(granted):
        raise CalendarError('Google Calendar read and event permissions are both required.')
    service = build('calendar', 'v3', http=AuthorizedHttp(credentials, http=httplib2.Http(timeout=30)), cache_discovery=False)
    primary = service.calendarList().get(calendarId='primary', fields='id').execute()
    store.store(TOKEN_NAME, credentials.to_json())
    return primary['id']


def event_id_for(agent: str, request_id: str) -> str:
    """A deterministic Google event ID, so a repeated insert is rejected by Google rather than duplicated."""
    digest = hashlib.sha256(f'agentgate\0{agent}\0{request_id}'.encode('utf-8')).digest()
    # Base32hex uses 0-9 and a-v, exactly the characters Google allows in event IDs.
    return base64.b32hexencode(digest).decode('ascii').rstrip('=').lower()


def _text(value: object, label: str, *, maximum: int, required: bool = False, single_line: bool = True) -> str:
    if not isinstance(value, str) or len(value) > maximum or _CONTROL.search(value):
        raise CalendarError(f'{label} must be text of at most {maximum} characters.')
    if single_line and ('\n' in value or '\r' in value):
        raise CalendarError(f'{label} must be a single line.')
    if required and not value.strip():
        raise CalendarError(f'{label} is required.')
    return value


def validate_calendar_id(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 256 or any(c.isspace() or ord(c) < 32 for c in value):
        raise CalendarError('calendar_id must be a calendar ID such as "primary".')
    return value


def _instant(value: object, label: str) -> dt.datetime:
    """An RFC 3339 timestamp with an explicit UTC offset."""
    if not isinstance(value, str) or len(value) > 64:
        raise CalendarError(f'{label} must be an RFC 3339 time with an offset, such as 2026-11-18T09:00:00-05:00.')
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00').replace('z', '+00:00'))
    except ValueError:
        parsed = None
    if parsed is None or parsed.tzinfo is None or 'T' not in value.upper():
        raise CalendarError(f'{label} must be an RFC 3339 time with an offset, such as 2026-11-18T09:00:00-05:00.')
    return parsed


def _stamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def _range(time_min: object, time_max: object, maximum: dt.timedelta) -> tuple[str, str]:
    start, end = _instant(time_min, 'time_min'), _instant(time_max, 'time_max')
    if end <= start:
        raise CalendarError('time_max must be after time_min.')
    if end - start > maximum:
        raise CalendarError(f'The time range must be at most {maximum.days} days.')
    return _stamp(start), _stamp(end)


def _limit(value: object, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise CalendarError(f'limit must be between 1 and {maximum}.')
    return value


def _page_token(value: object) -> str | None:
    if value is None or value == '':
        return None
    if not isinstance(value, str) or len(value) > 1024 or any(c.isspace() for c in value):
        raise CalendarError('page_token is invalid.')
    return value


def event_body(*, summary: object, start: object, end: object, time_zone: object = '',
               location: object = '', description: object = '') -> dict:
    """Validate an event request into the exact Google Calendar body that will be approved and inserted."""
    summary = _text(summary, 'summary', maximum=1024, required=True)
    location = _text(location, 'location', maximum=1024)
    description = _text(description, 'description', maximum=8192, single_line=False)
    time_zone = _text(time_zone, 'time_zone', maximum=64)
    if time_zone:
        try:
            ZoneInfo(time_zone)
        except (ZoneInfoNotFoundError, ValueError):
            raise CalendarError('time_zone must be an IANA time zone such as America/New_York.') from None
    if not isinstance(start, str) or not isinstance(end, str):
        raise CalendarError('start and end must be text.')
    if _DATE.fullmatch(start) or _DATE.fullmatch(end):
        if not (_DATE.fullmatch(start) and _DATE.fullmatch(end)):
            raise CalendarError('An all-day event needs dates (YYYY-MM-DD) for both start and end.')
        try:
            first, last = dt.date.fromisoformat(start), dt.date.fromisoformat(end)
        except ValueError:
            raise CalendarError('start and end must be valid dates.') from None
        if last <= first:
            raise CalendarError('An all-day event ends on a later date than it starts; the end date is exclusive.')
        if last - first > _MAX_EVENT_LENGTH:
            raise CalendarError('An event can last at most 31 days.')
        start_value, end_value = {'date': start}, {'date': end}
    else:
        first, last = _instant(start, 'start'), _instant(end, 'end')
        if last <= first:
            raise CalendarError('end must be after start.')
        if last - first > _MAX_EVENT_LENGTH:
            raise CalendarError('An event can last at most 31 days.')
        start_value, end_value = {'dateTime': first.isoformat()}, {'dateTime': last.isoformat()}
    if time_zone:
        start_value['timeZone'] = end_value['timeZone'] = time_zone
    body = {'summary': summary, 'start': start_value, 'end': end_value}
    if location:
        body['location'] = location
    if description:
        body['description'] = description
    return body


def _when(value: object) -> dict:
    if not isinstance(value, dict):
        return {}
    return {key: value[key] for key in ('date', 'dateTime', 'timeZone') if isinstance(value.get(key), str)}


def _event(item: object) -> dict:
    if not isinstance(item, dict):
        raise CalendarError('Google Calendar returned an unexpected event.')
    event = {key: item[key] for key in ('id', 'status', 'summary', 'location', 'htmlLink')
             if isinstance(item.get(key), str)}
    if isinstance(item.get('description'), str):
        event['description'] = item['description'][:2000]
    event['start'], event['end'] = _when(item.get('start')), _when(item.get('end'))
    organizer = item.get('organizer')
    if isinstance(organizer, dict) and isinstance(organizer.get('email'), str):
        event['organizer'] = organizer['email']
    attendees = item.get('attendees')
    if isinstance(attendees, list):
        event['attendees'] = [
            {key: person[key] for key in ('email', 'responseStatus') if isinstance(person.get(key), str)}
            for person in attendees[:50] if isinstance(person, dict)
        ]
    return event


class Calendar:
    def __init__(self, store: CredentialStore, service_factory: Callable | None = None, session=None):
        self.store = store
        self._factory = service_factory
        self._session = session or requests
        self._lock = threading.RLock()
        self._credentials = None
        self._service = None
        self._suspended = False

    def _load_credentials(self):
        try:
            saved = json.loads(self.store.retrieve(TOKEN_NAME))
        except KeyError:
            raise CalendarError(NOT_CONNECTED) from None
        self._credentials = Credentials(
            token=saved.get('token'), refresh_token=saved['refresh_token'],
            token_uri=TOKEN_URI, client_id=saved['client_id'],
            client_secret=saved['client_secret'], scopes=SCOPES,
        )
        # Refresh on first use; the stored access token may already have expired.
        self._refresh()

    def _get_service(self):
        if self._suspended:
            raise CalendarError(NOT_CONNECTED)
        if self._factory is not None:
            return self._factory()
        if self._credentials is None:
            self._load_credentials()
        elif not self._credentials.valid:
            self._refresh()
        if self._service is None:
            self._service = build('calendar', 'v3', http=AuthorizedHttp(self._credentials, http=httplib2.Http(timeout=30)), cache_discovery=False)
        return self._service

    def _refresh(self):
        request = Request()

        def bounded_request(*args, **kwargs):
            kwargs.setdefault('timeout', 30)
            return request(*args, **kwargs)
        self._credentials.refresh(bounded_request)
        # Disconnect can suspend the provider while a network refresh is in flight.
        # Never let that refresh write credentials back after local removal.
        if self._suspended:
            raise CalendarError(NOT_CONNECTED)
        self.store.store(TOKEN_NAME, self._credentials.to_json())

    def call(self, operation: str, *, before_dispatch: Callable[[], None] | None = None, **arguments):
        # googleapiclient's HTTP transport is not thread-safe; serialize calls.
        with self._lock:
            try:
                if self._suspended:
                    raise CalendarError(NOT_CONNECTED)
                handler = getattr(self, '_' + operation, None) if operation in (
                    'account', 'calendars', 'events', 'freebusy', 'create_event') else None
                if handler is None:
                    raise CalendarError('Unsupported Google Calendar operation.')
                service = self._get_service()
                if self._suspended:
                    raise CalendarError(NOT_CONNECTED)
                if operation == 'create_event':
                    # Validation runs first; the guard runs at the single POST.
                    return handler(service, before_dispatch=before_dispatch, **arguments)
                prepared = handler(service, **arguments)
                if before_dispatch is not None:
                    before_dispatch()
                return prepared()
            except RefreshError:
                self._credentials = None
                self._service = None
                raise CalendarError('Google authorization needs renewal. Reconnect Google Calendar.') from None
            except HttpError as exc:
                status = exc.resp.status
                if status == 401:
                    raise CalendarError('Google authorization needs renewal. Reconnect Google Calendar.') from None
                if status == 404:
                    raise CalendarError('That calendar was not found or is not shared with this account.') from None
                raise CalendarError(f'Google Calendar API request failed (HTTP {status}).') from None
            except (OSError, TimeoutError, TransportError, httplib2.HttpLib2Error, requests.RequestException):
                raise CalendarError('Google Calendar could not be reached. Check your connection.') from None

    # Each read validates its arguments and returns a thunk; ``call`` checks
    # the captured access guard between validation and the network request.

    def _account(self, service):
        def run():
            result = service.calendarList().get(calendarId='primary', fields='id').execute()
            if not isinstance(result, dict) or not isinstance(result.get('id'), str) or not result['id']:
                raise CalendarError('Google Calendar did not return an account.')
            return {'email': result['id']}
        return run

    def _calendars(self, service, limit: int = 50, page_token: str | None = None):
        arguments = {'maxResults': _limit(limit, 250)}
        token = _page_token(page_token)
        if token:
            arguments['pageToken'] = token

        def run():
            result = service.calendarList().list(**arguments).execute()
            items = result.get('items', []) if isinstance(result, dict) else []
            calendars = []
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get('id'), str):
                    continue
                calendars.append({
                    'id': item['id'],
                    'summary': item.get('summaryOverride') or item.get('summary') or item['id'],
                    'primary': item.get('primary') is True,
                    'access_role': item.get('accessRole'),
                    'time_zone': item.get('timeZone'),
                })
            return {'calendars': calendars, 'next_page_token': result.get('nextPageToken')}
        return run

    def _events(self, service, time_min: str, time_max: str, calendar_id: str = 'primary',
                query: str = '', limit: int = 25, page_token: str | None = None):
        start, end = _range(time_min, time_max, _MAX_EVENT_RANGE)
        arguments = {'calendarId': validate_calendar_id(calendar_id), 'timeMin': start, 'timeMax': end,
                     'singleEvents': True, 'orderBy': 'startTime', 'maxResults': _limit(limit, 100)}
        query = _text(query, 'query', maximum=256)
        if query.strip():
            arguments['q'] = query
        token = _page_token(page_token)
        if token:
            arguments['pageToken'] = token

        def run():
            result = service.events().list(**arguments).execute()
            items = result.get('items', []) if isinstance(result, dict) else []
            return {'calendar_id': arguments['calendarId'], 'time_zone': result.get('timeZone'),
                    'events': [_event(item) for item in items if isinstance(item, dict) and item.get('status') != 'cancelled'],
                    'next_page_token': result.get('nextPageToken')}
        return run

    def _freebusy(self, service, time_min: str, time_max: str, calendar_ids: list | None = None):
        start, end = _range(time_min, time_max, _MAX_FREEBUSY_RANGE)
        ids = ['primary'] if calendar_ids is None else calendar_ids
        if not isinstance(ids, list) or not 1 <= len(ids) <= 20:
            raise CalendarError('calendar_ids must list between 1 and 20 calendar IDs.')
        ids = [validate_calendar_id(value) for value in ids]
        body = {'timeMin': start, 'timeMax': end, 'items': [{'id': value} for value in ids]}

        def run():
            result = service.freebusy().query(body=body).execute()
            calendars = result.get('calendars', {}) if isinstance(result, dict) else {}
            busy = {}
            for value in ids:
                entry = calendars.get(value, {}) if isinstance(calendars, dict) else {}
                if not isinstance(entry, dict):
                    entry = {}
                intervals = [{'start': row['start'], 'end': row['end']} for row in entry.get('busy', [])
                             if isinstance(row, dict) and isinstance(row.get('start'), str) and isinstance(row.get('end'), str)]
                busy[value] = {'busy': intervals}
                if entry.get('errors'):
                    busy[value]['error'] = 'Free/busy information is not available for this calendar.'
            return {'time_min': start, 'time_max': end, 'calendars': busy}
        return run

    def _create_event(self, service, *, calendar_id: str, event_id: str, body: dict,
                      before_dispatch: Callable[[], None] | None = None):
        calendar_id = validate_calendar_id(calendar_id)
        if not isinstance(event_id, str) or not re.fullmatch(r'[0-9a-v]{5,1024}', event_id):
            raise CalendarError('The event ID is invalid.')
        if self._credentials is None:
            raise CalendarError(NOT_CONNECTED)
        # Renew immediately before dispatch so an approval wait or near-expiry
        # token does not require retrying a non-idempotent insert.
        self._refresh()
        if before_dispatch is not None:
            before_dispatch()
        if self._suspended:
            raise CalendarError(NOT_CONNECTED)
        # httplib2 can replay POSTs after response loss. A plain request with
        # redirects disabled dispatches once; the fixed event ID makes Google
        # reject any duplicate insert with HTTP 409.
        response = self._session.post(
            f'{API_BASE}/calendars/{quote(calendar_id, safe="")}/events',
            params={'sendUpdates': 'none'},
            headers={'Authorization': f'Bearer {self._credentials.token}'},
            json={**body, 'id': event_id}, timeout=30, allow_redirects=False,
        )
        if response.status_code == 409:
            raise CalendarError('An event for this request already exists in Google Calendar.')
        if response.status_code == 401:
            raise CalendarError('Google authorization needs renewal. Reconnect Google Calendar.')
        if response.status_code == 404:
            raise CalendarError('That calendar was not found or is not shared with this account.')
        if response.status_code != 200:
            raise CalendarError(f'Google Calendar API request failed (HTTP {response.status_code}).')
        try:
            result = response.json()
        except ValueError:
            raise CalendarError('Google Calendar returned an unexpected response.') from None
        if not isinstance(result, dict) or not isinstance(result.get('id'), str):
            raise CalendarError('Google Calendar returned an unexpected response.')
        return _event(result)
