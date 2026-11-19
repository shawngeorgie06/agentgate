"""Google Calendar provider, tool boundary, connection, and permission tests. All Google calls are faked."""
from __future__ import annotations

import asyncio
import dataclasses
import json

import pytest
import requests
from fastmcp import Client, FastMCP

from broker.calendar_tools import CalendarTools, register_calendar_tools
from broker.connections import CalendarConnection
from broker.grants import GrantError
from broker.integrations import calendar as calendar_module
from broker.integrations.calendar import (
    ACCOUNT_NAME, API_BASE, TOKEN_NAME, Calendar, CalendarError, event_body, event_id_for,
)
from broker.main import build_broker
from broker.policy_engine import PolicyEngine
from tests.test_github import MemoryStore, pending
from tests.test_github_permissions import github_selections
from tests.test_grants import setup as grant_setup
from tests.test_main import _cfg
from tests.test_permissions import selections, setup as permission_setup


class Request:
    def __init__(self, service, name, kwargs, result):
        self.service, self.name, self.kwargs, self.result = service, name, kwargs, result

    def execute(self):
        self.service.calls.append((self.name, self.kwargs))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class Resource:
    def __init__(self, service, prefix):
        self.service, self.prefix = service, prefix

    def __getattr__(self, method):
        name = f'{self.prefix}.{method}'
        return lambda **kwargs: Request(self.service, name, kwargs, self.service.results.get(name, {}))


class FakeService:
    def __init__(self, **results):
        self.results = {key.replace('_', '.'): value for key, value in results.items()}
        self.calls = []

    def calendarList(self):
        return Resource(self, 'calendarList')

    def events(self):
        return Resource(self, 'events')

    def freebusy(self):
        return Resource(self, 'freebusy')


class Credentials:
    token = 'access-private'
    valid = True

    def __init__(self):
        self.refreshes = 0

    def refresh(self, request):
        self.refreshes += 1

    def to_json(self):
        return json.dumps({'refresh_token': 'refresh-private'})


class Response:
    def __init__(self, status=200, data=None):
        self.status_code = status
        self._data = data

    def json(self):
        if isinstance(self._data, Exception):
            raise self._data
        return self._data


class Session:
    def __init__(self, responses=()):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def provider(service=None, responses=(), store=None):
    service = service or FakeService()
    calendar = Calendar(store or MemoryStore(None), service_factory=lambda: service, session=Session(responses))
    calendar._credentials = Credentials()
    return calendar, service


EVENT = {'summary': 'Dentist', 'start': '2026-11-20T09:00:00-05:00', 'end': '2026-11-20T10:00:00-05:00'}


# Provider validation and reads.

def test_event_body_builds_exact_timed_and_all_day_bodies():
    assert event_body(**EVENT, time_zone='America/New_York', location='Main St', description='Line 1\nLine 2') == {
        'summary': 'Dentist', 'location': 'Main St', 'description': 'Line 1\nLine 2',
        'start': {'dateTime': '2026-11-20T09:00:00-05:00', 'timeZone': 'America/New_York'},
        'end': {'dateTime': '2026-11-20T10:00:00-05:00', 'timeZone': 'America/New_York'},
    }
    assert event_body(summary='Trip', start='2026-12-01', end='2026-12-04') == {
        'summary': 'Trip', 'start': {'date': '2026-12-01'}, 'end': {'date': '2026-12-04'},
    }


@pytest.mark.parametrize('changes', [
    {'summary': ''}, {'summary': 'Two\nlines'}, {'summary': 'x' * 1025},
    {'start': '2026-11-20T09:00:00'},  # no offset
    {'end': '2026-11-20T08:00:00-05:00'},  # before start
    {'end': '2026-12-25T10:00:00-05:00'},  # longer than 31 days
    {'start': '2026-11-20', 'end': '2026-11-20'},  # exclusive end date
    {'start': '2026-11-20'},  # mixed date and time
    {'time_zone': 'Mars/Olympus'}, {'location': 'bad\x00'},
])
def test_event_body_rejects_invalid_requests(changes):
    with pytest.raises(CalendarError):
        event_body(**{**EVENT, **changes})


def test_event_id_is_stable_google_safe_and_scoped_to_agent():
    first = event_id_for('agent-a', 'request-1234567890')
    assert first == event_id_for('agent-a', 'request-1234567890')
    assert first != event_id_for('agent-b', 'request-1234567890')
    assert set(first) <= set('0123456789abcdefghijklmnopqrstuv') and 5 <= len(first) <= 1024


def test_reads_send_bounded_requests_and_return_safe_fields():
    service = FakeService(
        calendarList_list={'items': [{'id': 'me@example.test', 'summary': 'Me', 'primary': True,
                                      'accessRole': 'owner', 'timeZone': 'America/New_York', 'etag': 'x'}]},
        events_list={'timeZone': 'America/New_York', 'items': [
            {'id': 'e1', 'status': 'confirmed', 'summary': 'Standup', 'description': 'd' * 3000,
             'start': {'dateTime': '2026-11-20T09:00:00-05:00'}, 'end': {'dateTime': '2026-11-20T09:15:00-05:00'},
             'attendees': [{'email': 'a@example.test', 'responseStatus': 'accepted', 'comment': 'private'}],
             'conferenceData': {'secret': 'meeting-pin'}},
            {'id': 'gone', 'status': 'cancelled'},
        ]},
        freebusy_query={'calendars': {'primary': {'busy': [{'start': '2026-11-20T14:00:00Z', 'end': '2026-11-20T15:00:00Z'}]}}},
    )
    calendar, _ = provider(service)
    calendars = calendar.call('calendars', limit=10)
    assert calendars['calendars'] == [{'id': 'me@example.test', 'summary': 'Me', 'primary': True,
                                       'access_role': 'owner', 'time_zone': 'America/New_York'}]
    events = calendar.call('events', time_min='2026-11-20T00:00:00-05:00', time_max='2026-11-21T00:00:00-05:00', query='stand')
    assert [event['id'] for event in events['events']] == ['e1']
    assert len(events['events'][0]['description']) == 2000
    assert events['events'][0]['attendees'] == [{'email': 'a@example.test', 'responseStatus': 'accepted'}]
    assert 'meeting-pin' not in json.dumps(events)
    assert service.calls[1] == ('events.list', {
        'calendarId': 'primary', 'timeMin': '2026-11-20T05:00:00Z', 'timeMax': '2026-11-21T05:00:00Z',
        'singleEvents': True, 'orderBy': 'startTime', 'maxResults': 25, 'q': 'stand',
    })
    busy = calendar.call('freebusy', time_min='2026-11-20T00:00:00Z', time_max='2026-11-21T00:00:00Z')
    assert busy['calendars'] == {'primary': {'busy': [{'start': '2026-11-20T14:00:00Z', 'end': '2026-11-20T15:00:00Z'}]}}


@pytest.mark.parametrize('operation,arguments', [
    ('events', {'time_min': '2026-01-01T00:00:00Z', 'time_max': '2027-06-01T00:00:00Z'}),
    ('events', {'time_min': '2026-01-02T00:00:00Z', 'time_max': '2026-01-01T00:00:00Z'}),
    ('events', {'time_min': '2026-01-01', 'time_max': '2026-01-02'}),
    ('events', {'time_min': '2026-01-01T00:00:00Z', 'time_max': '2026-01-02T00:00:00Z', 'limit': 101}),
    ('events', {'time_min': '2026-01-01T00:00:00Z', 'time_max': '2026-01-02T00:00:00Z', 'calendar_id': 'a b'}),
    ('freebusy', {'time_min': '2026-01-01T00:00:00Z', 'time_max': '2026-03-15T00:00:00Z'}),
    ('freebusy', {'time_min': '2026-01-01T00:00:00Z', 'time_max': '2026-01-02T00:00:00Z', 'calendar_ids': []}),
    ('calendars', {'limit': 0}),
    ('calendars', {'page_token': 'has space'}),
    ('delete_event', {}),
])
def test_invalid_reads_never_reach_google(operation, arguments):
    calendar, service = provider()
    with pytest.raises(CalendarError):
        calendar.call(operation, **arguments)
    assert service.calls == []


def test_read_guard_runs_after_validation_and_before_request():
    calendar, service = provider()

    class Revoked(Exception):
        pass

    def guard():
        raise Revoked
    with pytest.raises(Revoked):
        calendar.call('calendars', before_dispatch=guard)
    assert service.calls == []


def test_unconnected_calendar_is_actionable_and_suspended_provider_never_calls():
    with pytest.raises(CalendarError, match='not connected'):
        Calendar(MemoryStore(None)).call('calendars')
    calendar, service = provider()
    calendar._suspended = True
    with pytest.raises(CalendarError, match='not connected'):
        calendar.call('calendars')
    assert service.calls == []


def test_create_event_posts_once_with_fixed_id_and_no_invitations():
    calendar, _ = provider(responses=[Response(data={'id': 'abc', 'status': 'confirmed', 'summary': 'Dentist',
                                                     'htmlLink': 'https://calendar.google.com/event?eid=abc'})])
    body = event_body(**EVENT)
    result = calendar.call('create_event', calendar_id='me@example.test', event_id='abcdefv012', body=body)
    assert result['id'] == 'abc'
    (url, options), = calendar._session.calls
    assert url == f'{API_BASE}/calendars/me%40example.test/events'
    assert options['params'] == {'sendUpdates': 'none'}
    assert options['json'] == {**body, 'id': 'abcdefv012'}
    assert options['allow_redirects'] is False and options['timeout'] == 30
    assert calendar._credentials.refreshes == 1


@pytest.mark.parametrize('response,message', [
    (Response(409), 'already exists'),
    (Response(401, {'error': 'access-private'}), 'Reconnect Google Calendar'),
    (Response(404), 'not found'),
    (Response(500, {'error': 'provider-detail'}), 'HTTP 500'),
    (requests.ConnectionError('socket detail'), 'could not be reached'),
])
def test_create_event_errors_are_safe_and_never_retried(response, message):
    calendar, _ = provider(responses=[response])
    with pytest.raises(CalendarError, match=message) as caught:
        calendar.call('create_event', calendar_id='primary', event_id='abcdefv012', body=event_body(**EVENT))
    assert 'detail' not in str(caught.value) and 'private' not in str(caught.value)
    assert len(calendar._session.calls) == 1


# Approval boundary.

def broker_tools(tmp_path, responses=(), service=None):
    broker = build_broker(_cfg(tmp_path), 'pw')
    broker.engine = PolicyEngine([{
        'name': 'calendar-all', 'agent': 'agent-a', 'credential': '*',
        'auto_approve': True, 'escalate': False,
    }])
    calendar, service = provider(service, responses, store=broker.store)
    return broker, calendar, service, CalendarTools(broker, calendar)


REQUEST = {**EVENT, 'request_id': 'request-1234567890'}


@pytest.mark.asyncio
@pytest.mark.parametrize('approve', [True, False])
async def test_event_creation_always_requires_approval_and_freezes_exact_payload(tmp_path, approve):
    broker, calendar, _, tools = broker_tools(tmp_path, [Response(data={'id': 'created', 'summary': 'Dentist'})])
    event = dict(REQUEST, description='Bring forms')
    task = asyncio.create_task(tools.create_event('agent-a', **event))
    request = await pending(broker)
    assert request.credential == 'calendar:write'
    frozen = json.loads(request.details)
    assert frozen == {'calendar_id': 'primary', 'event': {
        'summary': 'Dentist', 'description': 'Bring forms',
        'start': {'dateTime': '2026-11-20T09:00:00-05:00'}, 'end': {'dateTime': '2026-11-20T10:00:00-05:00'},
    }}
    assert calendar._session.calls == []
    event.update(summary='Changed while pending')
    broker.approvals.resolve(request, approve)
    result = await task
    assert result['ok'] is approve
    assert len(calendar._session.calls) == int(approve)
    if approve:
        sent = calendar._session.calls[0][1]['json']
        assert sent == {**frozen['event'], 'id': event_id_for('agent-a', 'request-1234567890')}
    assert 'Bring forms' not in open(broker.config.logs_path).read()


@pytest.mark.asyncio
async def test_expired_event_approval_never_dispatches(tmp_path):
    broker, calendar, _, tools = broker_tools(tmp_path, [Response(data={'id': 'created'})])
    broker.config = dataclasses.replace(broker.config, escalation_timeout_seconds=0.01)
    result = await tools.create_event('agent-a', **REQUEST)
    assert result['ok'] is False and 'timed out' in result['reason']
    assert calendar._session.calls == []


@pytest.mark.asyncio
async def test_revoked_access_after_approval_never_dispatches(tmp_path):
    broker, calendar, _, tools = broker_tools(tmp_path, [Response(data={'id': 'created'})])
    active = {'value': True}
    task = asyncio.create_task(tools.create_event('agent-a', **REQUEST, identity_guard=lambda: active['value']))
    request = await pending(broker)
    active['value'] = False
    broker.approvals.resolve(request, True)
    result = await task
    assert result['ok'] is False
    assert calendar._session.calls == []


@pytest.mark.asyncio
async def test_event_attempt_is_persisted_before_dispatch_and_duplicate_is_blocked(tmp_path):
    broker, calendar, _, tools = broker_tools(tmp_path, [requests.Timeout('response lost')])
    task = asyncio.create_task(tools.create_event('agent-a', **REQUEST))
    broker.approvals.resolve(await pending(broker), True)
    result = await task
    assert result['ok'] is False and 'uncertain' in result['reason'].lower()
    again = await CalendarTools(broker, calendar).create_event('agent-a', **REQUEST)
    assert again['ok'] is False and 'already has an attempt' in again['reason']
    assert len(calendar._session.calls) == 1
    assert 'request-1234567890' not in json.dumps(broker.store.retrieve('__agentgate:calendar-attempts'))


@pytest.mark.asyncio
@pytest.mark.parametrize('changes', [{'request_id': 'short'}, {'request_id': 'bad id with spaces!!'},
                                     {'end': '2026-11-20T08:00:00-05:00'}, {'calendar_id': ''}])
async def test_invalid_event_requests_fail_before_approval(tmp_path, changes):
    broker, calendar, _, tools = broker_tools(tmp_path)
    result = await tools.create_event('agent-a', **{**REQUEST, **changes})
    assert result['ok'] is False
    assert broker.approvals.get_pending() is None


@pytest.mark.asyncio
async def test_denied_read_never_reaches_google(tmp_path):
    broker, _, service, tools = broker_tools(tmp_path)
    broker.engine = PolicyEngine([{'name': 'deny', 'agent': 'agent-a', 'credential': 'calendar:read',
                                   'auto_approve': False, 'escalate': False}])
    result = await tools.execute('agent-a', 'calendar:read', 'calendars')
    assert result['ok'] is False
    assert service.calls == []


@pytest.mark.asyncio
async def test_registration_requires_identity_and_uses_server_resolved_agent(tmp_path):
    broker, _, service, tools = broker_tools(tmp_path, service=FakeService(calendarList_list={'items': []}))
    with pytest.raises(ValueError):
        register_calendar_tools(FastMCP('no identity'), broker, tools=tools)
    mcp = FastMCP('Calendar tool test')
    register_calendar_tools(mcp, broker, tools=tools, identity_resolver=lambda _supplied: ('agent-a', lambda: True))
    async with Client(mcp) as client:
        names = {tool.name for tool in await client.list_tools()}
        result = (await client.call_tool('calendar.calendars', {'agent': 'attacker', 'limit': 5})).data
    assert {'calendar.calendars', 'calendar.events', 'calendar.freebusy', 'calendar.create_event'} <= names
    assert result['ok'] is True
    assert service.calls == [('calendarList.list', {'maxResults': 5})]


# Connection, permissions, and grants.

class AccountService(FakeService):
    def __init__(self):
        super().__init__(calendarList_get={'id': 'owner@example.test'})


def test_connection_info_caches_account_and_disconnect_removes_credentials(tmp_path):
    broker = build_broker(_cfg(tmp_path), 'pw')
    service = AccountService()
    calendar = Calendar(broker.store, service_factory=lambda: service)
    broker.store.store(TOKEN_NAME, '{"refresh_token":"refresh-private"}')
    connection = CalendarConnection(broker, calendar, 'oauth-client.json')
    info = connection.info()
    assert info == {'service': 'calendar', 'status': 'connected',
                    'account': {'email': 'owner@example.test'}, 'reconnecting': False}
    assert 'refresh-private' not in json.dumps(info)
    connection.disconnect()
    assert TOKEN_NAME not in broker.store.list_names()
    assert ACCOUNT_NAME not in broker.store.list_names()
    with pytest.raises(CalendarError, match='not connected'):
        calendar.call('calendars')


@pytest.mark.asyncio
async def test_calendar_reconnect_uses_calendar_oauth_and_keeps_gmail_token(tmp_path, monkeypatch):
    from broker.integrations.gmail import TOKEN_NAME as GMAIL_TOKEN
    broker = build_broker(_cfg(tmp_path), 'pw')
    broker.store.store(GMAIL_TOKEN, '{"refresh_token":"gmail-private"}')
    calendar = Calendar(broker.store, service_factory=AccountService)
    connection = CalendarConnection(broker, calendar, 'oauth-client.json')

    def fake_connect(client_file, capture_store):
        capture_store.store(TOKEN_NAME, '{"refresh_token":"calendar-new"}')
        return 'owner@example.test'
    monkeypatch.setattr(calendar_module, 'connect', fake_connect)
    connection.begin_reconnect()
    async with asyncio.timeout(2):
        while connection.reconnect_status()['active']:
            await asyncio.sleep(0.01)
    assert connection.reconnect_status()['state'] == 'completed'
    assert json.loads(broker.store.retrieve(TOKEN_NAME)) == {'refresh_token': 'calendar-new'}
    assert json.loads(broker.store.retrieve(GMAIL_TOKEN)) == {'refresh_token': 'gmail-private'}
    assert json.loads(broker.store.retrieve(ACCOUNT_NAME)) == {'email': 'owner@example.test'}


def test_calendar_permissions_are_scoped_and_writes_cannot_be_auto_allowed(tmp_path):
    broker, _, _, _, permissions = permission_setup(tmp_path)
    permissions.save('local-agent', selections(), permissions.view('local-agent')['revision'])
    permissions.save('local-agent', github_selections(), permissions.view('local-agent', 'github')['revision'], service='github')
    view = permissions.view('local-agent', service='calendar')
    assert view['permissions'] == {'calendar:read': 'ask', 'calendar:write': 'ask'}
    with pytest.raises(ValueError):
        permissions.save('local-agent', {'calendar:read': 'allow', 'calendar:write': 'allow'},
                         view['revision'], service='calendar')
    saved = permissions.save('local-agent', {'calendar:read': 'allow', 'calendar:write': 'ask'},
                             view['revision'], service='calendar')
    assert saved['permissions'] == {'calendar:read': 'allow', 'calendar:write': 'ask'}
    assert broker.engine.evaluate('local-agent', 'calendar:read').auto_approve is True
    assert broker.engine.evaluate('local-agent', 'gmail:read').auto_approve is True
    assert broker.engine.evaluate('local-agent', 'github:read').auto_approve is True


def test_calendar_grants_allow_reads_and_only_ask_for_writes(tmp_path):
    _, _, grants = grant_setup(tmp_path)
    assert grants.create('worker', 'calendar:read', 'allow', 5)['resource'] == 'calendar:read'
    assert grants.create('worker', 'calendar:write', 'ask', 5)['permission'] == 'ask'
    with pytest.raises(GrantError):
        grants.create('worker', 'calendar:write', 'allow', 5)


@pytest.mark.asyncio
@pytest.mark.parametrize('change', ['revoke', 'disconnect'])
async def test_access_change_during_ledger_write_stops_dispatch(tmp_path, change):
    broker, calendar, _, tools = broker_tools(tmp_path, [Response(data={'id': 'created'})])
    active = {'value': True}
    store = broker.store.store

    def slow_store(name, value):
        store(name, value)
        if name == '__agentgate:calendar-attempts':
            if change == 'revoke':
                active['value'] = False
            else:
                calendar._suspended = True
    broker.store.store = slow_store
    task = asyncio.create_task(tools.create_event('agent-a', **REQUEST, identity_guard=lambda: active['value']))
    broker.approvals.resolve(await pending(broker), True)
    result = await task
    assert result['ok'] is False
    assert calendar._session.calls == []
    again = await tools.create_event('agent-a', **REQUEST)
    assert again['ok'] is False and 'already has an attempt' in again['reason']
