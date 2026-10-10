import asyncio
import base64
import dataclasses
import json
from email.message import EmailMessage
from types import SimpleNamespace

import pytest
from fastmcp import Client, FastMCP
from google.auth.exceptions import RefreshError
from googleapiclient.errors import HttpError

from broker.gmail_tools import GmailTools, register_gmail_tools
from broker.integrations.gmail import Gmail, GmailError, TOKEN_NAME, SCOPES, describe_message
from broker.main import build_broker
from broker.policy_engine import PolicyEngine
from tests.test_main import _cfg


def raw_message(body='Hello!', to='recipient@example.test'):
    message = EmailMessage()
    message['To'] = to
    message['Subject'] = 'Test subject'
    message.set_content(body)
    return base64.urlsafe_b64encode(message.as_bytes()).decode()


class FakeService:
    def __init__(self):
        self.calls = []
        self.raw = raw_message()
        self.error = None

    def users(self):
        return self

    def messages(self):
        self.endpoint = 'messages'
        return self

    def drafts(self):
        self.endpoint = 'drafts'
        return self

    def get(self, **kwargs):
        self.calls.append((self.endpoint, 'get', kwargs))
        result = {'id': 'message-1', 'raw': self.raw, 'threadId': 'thread-1'}
        return SimpleNamespace(execute=lambda: {'id': 'draft-1', 'message': result} if self.endpoint == 'drafts' else result)

    def list(self, **kwargs):
        self.calls.append((self.endpoint, 'list', kwargs))
        return SimpleNamespace(execute=lambda: {'messages': [{'id': 'message-1'}], 'nextPageToken': 'next'})

    def create(self, **kwargs):
        self.calls.append((self.endpoint, 'create', kwargs))
        return SimpleNamespace(execute=lambda: {'id': 'draft-1'})

    def send(self, **kwargs):
        self.calls.append((self.endpoint, 'send', kwargs))
        def execute():
            if self.error:
                raise self.error
            return {'id': 'sent-1'}
        return SimpleNamespace(execute=execute)


def make_tools(tmp_path):
    broker = build_broker(_cfg(tmp_path), 'pw')
    broker.engine = PolicyEngine([{
        'name': 'local-gmail', 'agent': 'local-agent', 'credential': '*',
        'auto_approve': True, 'escalate': False,
    }])
    service = FakeService()
    gmail = Gmail(broker.store, service_factory=lambda: service)
    return broker, service, gmail, GmailTools(broker, gmail)


async def pending(broker):
    async with asyncio.timeout(3):
        while broker.approvals.get_pending() is None:
            await asyncio.sleep(0.01)
    return broker.approvals.get_pending()


@pytest.mark.asyncio
async def test_mcp_search_read_and_create_draft(tmp_path):
    broker, service, gmail, _ = make_tools(tmp_path)
    mcp = FastMCP('Gmail test')
    register_gmail_tools(mcp, broker, gmail)
    async with Client(mcp) as client:
        search = (await client.call_tool('gmail.search', {'agent': 'local-agent', 'query': 'is:unread'})).data
        assert search['data']['messages'][0]['id'] == 'message-1'
        read = (await client.call_tool('gmail.read', {'agent': 'local-agent', 'message_id': 'message-1'})).data
        assert read['data']['parts'][0]['content'] == 'Hello!\n'
        draft = (await client.call_tool('gmail.draft', {
            'agent': 'local-agent', 'to': 'recipient@example.test', 'subject': 'Subject', 'body': 'Body',
        })).data
        assert draft['data']['id'] == 'draft-1'
    assert not any(call[1] == 'send' for call in service.calls)
    assert 'Body' not in open(broker.config.logs_path).read()


@pytest.mark.asyncio
@pytest.mark.parametrize('approve', [True, False])
async def test_send_requires_approval_even_under_auto_policy(tmp_path, approve):
    broker, service, _, tools = make_tools(tmp_path)
    task = asyncio.create_task(tools.send_draft('local-agent', 'draft-1'))
    request = await pending(broker)
    preview = json.loads(request.details)
    assert preview['to'] == ['recipient@example.test']
    assert preview['subject'] == 'Test subject'
    assert preview['parts'][0]['content'] == 'Hello!\n'
    assert request.credential == 'gmail:send'
    assert not any(call[1] == 'send' for call in service.calls)
    approved_raw = service.raw
    # Simulate the draft changing in Gmail while approval is pending.
    service.raw = raw_message('Modified after review', 'other@example.test')
    broker.approvals.resolve(request, approve)
    result = await task
    assert result['ok'] is approve
    sends = [call for call in service.calls if call[1] == 'send']
    assert len(sends) == int(approve)
    if approve:
        assert sends[0][2]['body']['raw'] == approved_raw
        assert result['draft_retained'] is True
    audit = open(broker.config.logs_path).read()
    assert 'recipient@example.test' not in audit
    assert 'Hello!' not in audit


@pytest.mark.asyncio
async def test_timeout_does_not_send(tmp_path):
    broker, service, _, tools = make_tools(tmp_path)
    broker.config = dataclasses.replace(broker.config, escalation_timeout_seconds=0.01)
    result = await tools.send_draft('local-agent', 'draft-1')
    assert not result['ok']
    assert not any(call[1] == 'send' for call in service.calls)
    assert broker.approvals.pending_count() == 0


@pytest.mark.asyncio
async def test_internal_google_credentials_never_exported(tmp_path):
    broker, _, _, _ = make_tools(tmp_path)
    broker.store.store(TOKEN_NAME, 'secret-refresh-token')
    result = await broker.request_credential('local-agent', TOKEN_NAME)
    assert result['granted'] is False
    assert result['value'] is None
    assert 'secret-refresh-token' not in open(broker.config.logs_path).read()


@pytest.mark.asyncio
async def test_explicit_deny_never_calls_gmail(tmp_path):
    broker, service, _, tools = make_tools(tmp_path)
    broker.engine = PolicyEngine([{
        'name': 'deny', 'agent': '*', 'credential': '*', 'auto_approve': False, 'escalate': False,
    }])
    result = await tools.execute('local-agent', 'gmail:read', 'search', query='secret')
    assert not result['ok']
    assert service.calls == []


@pytest.mark.asyncio
async def test_duplicate_send_attempt_blocked_across_tool_restart(tmp_path):
    broker, service, gmail, tools = make_tools(tmp_path)
    task = asyncio.create_task(tools.send_draft('local-agent', 'draft-1'))
    broker.approvals.resolve(await pending(broker), True)
    assert (await task)['ok']
    restarted = GmailTools(broker, gmail)
    assert not (await restarted.send_draft('local-agent', 'draft-1'))['ok']
    assert len([call for call in service.calls if call[1] == 'send']) == 1


@pytest.mark.asyncio
async def test_send_http_error_is_sanitized_and_not_retried(tmp_path):
    broker, service, gmail, tools = make_tools(tmp_path)
    service.error = HttpError(SimpleNamespace(status=503, reason='Error'), b'{"error":"secret-value"}')
    task = asyncio.create_task(tools.send_draft('local-agent', 'draft-1'))
    broker.approvals.resolve(await pending(broker), True)
    result = await task
    assert not result['ok']
    assert 'secret-value' not in result['reason']
    assert 'uncertain' in result['reason']
    assert not (await GmailTools(broker, gmail).send_draft('local-agent', 'draft-1'))['ok']
    assert len([call for call in service.calls if call[1] == 'send']) == 1


def test_unconnected_gmail_returns_actionable_error(tmp_path):
    broker = build_broker(_cfg(tmp_path), 'pw')
    with pytest.raises(GmailError, match='not connected'):
        Gmail(broker.store).call('search', query='test')


def test_refresh_tokens_stay_encrypted_and_refresh_runs_once(tmp_path, monkeypatch):
    broker, service, _, _ = make_tools(tmp_path)
    broker.store.store(TOKEN_NAME, json.dumps({
        'token': 'access-secret', 'refresh_token': 'refresh-secret',
        'client_id': 'client', 'client_secret': 'client-secret',
    }))
    from broker.integrations import gmail as module
    refreshed = []
    class FakeCredentials:
        def __init__(self, **kwargs):
            assert kwargs['refresh_token'] == 'refresh-secret'
            assert kwargs['token_uri'] == module.TOKEN_URI
            self.valid = False
        def refresh(self, request):
            refreshed.append(True)
            self.valid = True
        def to_json(self):
            return '{"refresh_token":"rotated-refresh-secret"}' 
    monkeypatch.setattr(module, 'Credentials', FakeCredentials)
    monkeypatch.setattr(module, 'AuthorizedHttp', lambda *a, **k: object())
    monkeypatch.setattr(module, 'build', lambda *a, **k: service)
    gmail = Gmail(broker.store)
    gmail.call('search', query='test')
    gmail.call('search', query='test')
    assert refreshed == [True]
    assert json.loads(broker.store.retrieve(TOKEN_NAME))['refresh_token'] == 'rotated-refresh-secret'
    encrypted = open(broker.config.credentials_path).read()
    for secret in ('access-secret', 'refresh-secret', 'client-secret'):
        assert secret not in encrypted


def test_revoked_token_error_does_not_leak_details(tmp_path):
    broker, _, _, _ = make_tools(tmp_path)
    def failure():
        raise RefreshError('sensitive-provider-details')
    with pytest.raises(GmailError, match='Reconnect Gmail') as error:
        Gmail(broker.store, failure).call('search', query='test')
    assert 'sensitive-provider-details' not in str(error.value)


@pytest.mark.parametrize('to,subject', [('x\nBcc: bad@example.test', 'ok'), ('x@example.test', 'x\r\nInjected: yes')])
def test_header_injection_rejected(tmp_path, to, subject):
    _, service, gmail, _ = make_tools(tmp_path)
    with pytest.raises(GmailError, match='headers'):
        gmail.call('draft', to=to, subject=subject, body='test')
    assert service.calls == []


@pytest.mark.asyncio
async def test_canceled_approval_removed_from_queue(tmp_path):
    broker, _, _, tools = make_tools(tmp_path)
    task = asyncio.create_task(tools.send_draft('local-agent', 'draft-1'))
    await pending(broker)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert broker.approvals.pending_count() == 0
    assert not broker.approvals._queue


def test_connect_stores_google_credentials_encrypted(tmp_path, monkeypatch):
    from broker.integrations import gmail as module
    broker, _, _, _ = make_tools(tmp_path)
    arguments = {}
    credentials = SimpleNamespace(
        refresh_token='refresh-secret', granted_scopes=SCOPES,
        to_json=lambda: '{"refresh_token":"refresh-secret"}',
    )
    class Flow:
        @staticmethod
        def from_client_secrets_file(client_file, scopes, **kwargs):
            assert scopes == SCOPES
            assert kwargs['autogenerate_code_verifier']
            return Flow()
        def run_local_server(self, **kwargs):
            arguments.update(kwargs)
            return credentials
    profile = SimpleNamespace(execute=lambda: {'emailAddress': 'user@example.test'})
    fake = SimpleNamespace(users=lambda: SimpleNamespace(getProfile=lambda **kwargs: profile))
    monkeypatch.setattr(module, 'InstalledAppFlow', Flow)
    monkeypatch.setattr(module, 'AuthorizedHttp', lambda *a, **k: object())
    monkeypatch.setattr(module, 'build', lambda *a, **k: fake)
    assert module.connect('client.json', broker.store) == 'user@example.test'
    assert arguments['host'] == '127.0.0.1'
    assert arguments['port'] == 0
    assert arguments['access_type'] == 'offline'
    assert 'refresh-secret' not in open(broker.config.credentials_path).read()
    assert json.loads(broker.store.retrieve(TOKEN_NAME))['refresh_token'] == 'refresh-secret'


def test_connect_requires_offline_authorization(tmp_path, monkeypatch):
    from broker.integrations import gmail as module
    broker, _, _, _ = make_tools(tmp_path)
    credentials = SimpleNamespace(refresh_token=None)
    flow = SimpleNamespace(run_local_server=lambda **kwargs: credentials)
    monkeypatch.setattr(module.InstalledAppFlow, 'from_client_secrets_file', lambda *a, **k: flow)
    with pytest.raises(GmailError, match='offline'):
        module.connect('client.json', broker.store)
    assert TOKEN_NAME not in broker.store.list_names()


def test_send_transport_does_not_replay_after_response_loss(tmp_path, monkeypatch):
    """Exercise the real requests transport against a local server losing its response."""
    import threading
    import requests
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from broker.integrations import gmail as module

    attempts = []
    class DropResponse(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            attempts.append(True)
            self.close_connection = True
        def log_message(self, *args):
            pass
    server = HTTPServer(('127.0.0.1', 0), DropResponse)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    real_post = requests.post
    def local_post(url, **kwargs):
        assert url == 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send'
        assert kwargs['allow_redirects'] is False
        assert kwargs['timeout'] == 30
        # Only the test changes the destination; production uses fixed Google URL.
        return real_post(f'http://127.0.0.1:{server.server_port}/send', **kwargs)
    monkeypatch.setattr(module.requests, 'post', local_post)
    broker, _, _, _ = make_tools(tmp_path)
    gmail = Gmail(broker.store)
    gmail._credentials = SimpleNamespace(token='dummy-token', valid=True)
    gmail._service = object()
    gmail._refresh = lambda: None
    try:
        with pytest.raises(GmailError, match='could not be reached'):
            gmail.call('send', snapshot={'raw': raw_message()})
        assert attempts == [True]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_send_renews_token_before_dispatch_without_retry(tmp_path, monkeypatch):
    from broker.integrations import gmail as module
    broker, _, _, _ = make_tools(tmp_path)
    gmail = Gmail(broker.store)
    gmail._credentials = SimpleNamespace(token='old-token', valid=True)
    gmail._service = object()
    events = []
    def refresh():
        events.append('refresh')
        gmail._credentials.token = 'fresh-token'
    def post(url, **kwargs):
        events.append('send')
        assert kwargs['headers']['Authorization'] == 'Bearer fresh-token'
        return SimpleNamespace(status_code=401)
    gmail._refresh = refresh
    monkeypatch.setattr(module.requests, 'post', post)
    with pytest.raises(GmailError, match='HTTP 401'):
        gmail.call('send', snapshot={'raw': raw_message()})
    assert events == ['refresh', 'send']
