"""Single-account Gmail API access with encrypted OAuth credentials."""
from __future__ import annotations

import base64
import hashlib
import json
import re
import threading
import httplib2
import requests
from google_auth_httplib2 import AuthorizedHttp
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from typing import Callable

from google.auth.exceptions import RefreshError, TransportError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from broker.credential_store import CredentialStore

INTERNAL_PREFIX = '__agentgate:'
TOKEN_NAME = INTERNAL_PREFIX + 'gmail-oauth'
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.compose',
]
TOKEN_URI = 'https://oauth2.googleapis.com/token'


class GmailError(Exception):
    """A safe error message that can be returned to an agent."""


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
        raise GmailError('Google did not issue offline access; reconnect Gmail.')
    granted = credentials.granted_scopes
    if granted is not None and not set(SCOPES).issubset(granted):
        raise GmailError('Gmail read and compose permissions are both required.')
    service = build('gmail', 'v1', http=AuthorizedHttp(credentials, http=httplib2.Http(timeout=30)), cache_discovery=False)
    profile = service.users().getProfile(userId='me').execute()
    store.store(TOKEN_NAME, credentials.to_json())
    return profile['emailAddress']


def decode_raw(raw: str) -> bytes:
    try:
        return base64.b64decode(raw + '=' * (-len(raw) % 4), altchars=b'-_', validate=True)
    except (ValueError, TypeError) as exc:
        raise GmailError('Gmail returned an invalid message.') from exc


def describe_message(raw: str) -> dict:
    content = decode_raw(raw)
    message = BytesParser(policy=policy.default).parsebytes(content)
    parts = []
    attachments = []
    for part in message.walk():
        if part.is_multipart():
            continue
        if part.get_content_disposition() == 'attachment' or part.get_filename():
            attachments.append({'filename': part.get_filename(), 'type': part.get_content_type()})
        elif part.get_content_maintype() == 'text':
            try:
                text = part.get_content()
            except (LookupError, UnicodeError):
                raise GmailError('This message uses an unsupported text encoding.') from None
            parts.append({'type': part.get_content_type(), 'content': text})
    return {
        'from': message.get_all('From', []),
        'to': message.get_all('To', []),
        'cc': message.get_all('Cc', []),
        'bcc': message.get_all('Bcc', []),
        'reply_to': message.get_all('Reply-To', []),
        'content_type': message.get_content_type(),
        # Raw, unfolded values: decoding drops comments that would still be sent.
        'headers': [[name.lower(), re.sub(r'\r?\n(?=[ \t])', '', value)] for name, value in message.raw_items()],
        'subject': message.get('Subject', ''),
        'date': message.get('Date', ''),
        'parts': parts,
        'attachments': attachments,
        'sha256': hashlib.sha256(content).hexdigest(),
    }


class Gmail:
    def __init__(self, store: CredentialStore, service_factory: Callable | None = None):
        self.store = store
        self._factory = service_factory
        self._lock = threading.RLock()
        self._credentials = None
        self._service = None
        self._suspended = False

    def _get_service(self):
        if self._suspended:
            raise GmailError('Gmail is not connected. Run gmail-connect in the operator CLI.')
        if self._factory is not None:
            return self._factory()
        if self._credentials is None:
            try:
                saved = json.loads(self.store.retrieve(TOKEN_NAME))
            except KeyError:
                raise GmailError('Gmail is not connected. Run gmail-connect in the operator CLI.') from None
            self._credentials = Credentials(
                token=saved.get('token'), refresh_token=saved['refresh_token'],
                token_uri=TOKEN_URI, client_id=saved['client_id'],
                client_secret=saved['client_secret'], scopes=SCOPES,
            )
            # Refresh on first use; the stored access token may already have expired.
            self._refresh()
        elif not self._credentials.valid:
            self._refresh()
        if self._service is None:
            self._service = build('gmail', 'v1', http=AuthorizedHttp(self._credentials, http=httplib2.Http(timeout=30)), cache_discovery=False)
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
            raise GmailError('Gmail is not connected. Run gmail-connect in the operator CLI.')
        self.store.store(TOKEN_NAME, self._credentials.to_json())

    def call(self, operation: str, *, before_dispatch: Callable[[], None] | None = None, **arguments) -> dict:
        # googleapiclient's HTTP transport is not thread-safe; serialize calls.
        with self._lock:
            try:
                if self._suspended:
                    raise GmailError('Gmail is not connected. Run gmail-connect in the operator CLI.')
                service = self._get_service()
                if self._suspended:
                    raise GmailError('Gmail is not connected. Run gmail-connect in the operator CLI.')
                if before_dispatch is not None:
                    before_dispatch()
                if operation == 'send':
                    arguments['before_dispatch'] = before_dispatch
                return getattr(self, '_' + operation)(service, **arguments)
            except RefreshError:
                self._credentials = None
                self._service = None
                raise GmailError('Google authorization needs renewal. Reconnect Gmail.') from None
            except HttpError as exc:
                raise GmailError(f'Gmail API request failed (HTTP {exc.resp.status}).') from None
            except (OSError, TimeoutError, TransportError, httplib2.HttpLib2Error, requests.RequestException):
                raise GmailError('Gmail could not be reached. Check your connection.') from None

    def _search(self, service, query: str, limit: int = 20, page_token: str | None = None):
        if not 1 <= limit <= 100:
            raise GmailError('limit must be between 1 and 100.')
        args = {'userId': 'me', 'q': query, 'maxResults': limit}
        if page_token:
            args['pageToken'] = page_token
        return service.users().messages().list(**args).execute()

    def _account(self, service):
        profile = service.users().getProfile(userId='me', fields='emailAddress').execute()
        email = profile.get('emailAddress')
        if not isinstance(email, str) or not email:
            raise GmailError('Gmail did not return an account address.')
        return {'email': email}

    def _read(self, service, message_id: str):
        result = service.users().messages().get(userId='me', id=message_id, format='raw').execute()
        return {'id': result['id'], 'thread_id': result.get('threadId'), **describe_message(result['raw'])}

    def _inbox(self, service, query: str = 'in:inbox', page_token: str | None = None):
        result = self._search(service, query, limit=10, page_token=page_token)
        messages = []
        for item in result.get('messages', []):
            message = self._read(service, item['id'])
            plain = next((p['content'] for p in message['parts'] if p['type'] == 'text/plain'), '')
            messages.append({key: message[key] for key in ('id', 'from', 'subject', 'date')} | {'snippet': plain[:180]})
        return {'messages': messages, 'next_page_token': result.get('nextPageToken')}

    def _drafts(self, service, page_token: str | None = None):
        arguments = {'userId': 'me', 'maxResults': 10}
        if page_token:
            arguments['pageToken'] = page_token
        result = service.users().drafts().list(**arguments).execute()
        drafts = []
        for item in result.get('drafts', []):
            preview = self._snapshot(service, item['id'])['preview']
            drafts.append({'id': item['id'], **preview})
        return {'drafts': drafts, 'next_page_token': result.get('nextPageToken')}

    def _draft(self, service, to: str, subject: str, body: str, cc: str = '', bcc: str = ''):
        if not to.strip():
            raise GmailError('A recipient is required.')
        message = EmailMessage()
        try:
            message['To'] = to
            message['Subject'] = subject
            if cc:
                message['Cc'] = cc
            if bcc:
                message['Bcc'] = bcc
        except ValueError:
            raise GmailError('Email headers must not contain newlines.') from None
        message.set_content(body)
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode('ascii')
        return service.users().drafts().create(userId='me', body={'message': {'raw': raw}}).execute()

    def _snapshot(self, service, draft_id: str):
        draft = service.users().drafts().get(userId='me', id=draft_id, format='raw').execute()
        message = draft['message']
        # Snapshot the actual draft before operator review; do not refetch at send time.
        return {'raw': message['raw'], 'threadId': message.get('threadId'),
                'preview': describe_message(message['raw'])}

    def _send(self, service, snapshot: dict, before_dispatch: Callable[[], None] | None = None):
        payload = {'raw': snapshot['raw']}
        if snapshot.get('threadId'):
            payload['threadId'] = snapshot['threadId']
        # Sending the approved bytes avoids draft edits changing an approved email.
        # Keep the original draft: deleting it could discard concurrent user edits.
        if self._factory is not None:
            if before_dispatch is not None:
                before_dispatch()
            return service.users().messages().send(userId='me', body=payload).execute()
        # Renew immediately before dispatch so an approval wait or near-expiry
        # token does not require retrying a non-idempotent send.
        self._refresh()
        if before_dispatch is not None:
            before_dispatch()
        # httplib2 can replay POSTs after response loss. Requests' stock adapter
        # disables retries; disable redirects too, so this dispatch happens once.
        response = requests.post(
            'https://gmail.googleapis.com/gmail/v1/users/me/messages/send',
            headers={'Authorization': f'Bearer {self._credentials.token}'},
            json=payload, timeout=30, allow_redirects=False,
        )
        if response.status_code != 200:
            raise GmailError(f'Gmail API request failed (HTTP {response.status_code}).')
        try:
            result = response.json()
        except ValueError:
            raise GmailError('Gmail returned an unexpected send response.') from None
        if not isinstance(result, dict) or not result.get('id'):
            raise GmailError('Gmail returned an unexpected send response.')
        return result
