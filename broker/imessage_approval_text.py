"""The iMessage text announcing a pending AgentGate approval.

A code is offered only when the text shows everything the request would send.
Agent-written text can hide data in characters the phone does not show, in
headers the text leaves out, or in layout that imitates the trusted fields, so
anything outside a narrow shape gets dashboard-only text with no code.
"""

from __future__ import annotations

import json
import re
import unicodedata
from email.utils import format_datetime, getaddresses, parsedate_to_datetime

EMAIL_SEND = 'gmail:send'
GITHUB_WRITE = 'github:write'
READ_PERMISSIONS = {'gmail:read': 'Gmail', 'github:read': 'GitHub'}
SUMMARY_LIMIT = 300
BODY_LIMIT = 200

_PLAIN_GITHUB_NAME = re.compile(r'[A-Za-z0-9_.-]{1,100}')
_GMAIL_MESSAGE_ID = re.compile(r'<[A-Za-z0-9+_=.-]{1,200}@mail\.gmail\.com>')
# Gmail writes the account's display name into From; only plain names are shown as written.
_PLAIN_FROM = re.compile(r"([A-Za-z0-9][A-Za-z0-9 .'-]{0,62}[A-Za-z0-9.]) <([^<>]+)>")
# The trace header Gmail adds to every draft created through its API, unfolded.
_GMAIL_RECEIVED = re.compile(r'from \d{1,30}\tnamed unknown\tby gmailapi\.google\.com\twith HTTPREST;\t(.+)')
_TEXT_PLAIN = re.compile(r'text/plain(?:;\s*charset="?(?:utf-8|us-ascii)"?)?', re.IGNORECASE)
_TRANSFER_ENCODINGS = frozenset({'7bit', '8bit', 'quoted-printable', 'base64'})
_REPEATABLE_HEADERS = frozenset({'to', 'cc', 'bcc'})
# Default-ignorable code points outside the C* categories, plus blanks that render as nothing.
_INVISIBLE = frozenset('͏ᅟᅠ឴឵᠋᠌᠍᠏ㅤﾠ⠀' + '\U00016fe4')


def _shown_as_written(character: str) -> bool:
    """False for characters the phone hides, replaces, or reorders around (right-to-left letters)."""
    if character == ' ':
        return True
    code = ord(character)
    return not (unicodedata.category(character)[0] in 'CZ' or character in _INVISIBLE or character == '\ufffd'
                or unicodedata.bidirectional(character) in ('R', 'AL', 'AN')
                or 0xFE00 <= code <= 0xFE0F or 0xE0000 <= code <= 0xE0FFF)


def _one_line(text: str) -> bool:
    """True when the phone shows text exactly: visible characters and single inner spaces only."""
    return (text == text.strip(' ') and '  ' not in text
            and all(_shown_as_written(character) for character in text))


def _body_lines(text: str):
    """Body lines as written, or None when any line hides characters or layout."""
    lines = text.replace('\r\n', '\n').rstrip('\n').split('\n')
    if text and lines == ['']:
        return None
    if any(not _one_line(line) for line in lines) or '\n\n\n' in '\n'.join(lines):
        return None
    return lines if text else []


def _details(pending):
    try:
        value = json.loads(pending.details) if pending.details else None
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _field(details, key):
    """A one-line string field with double quotes dropped so quoting can delimit it.

    '' when absent; None when it is not text or the phone would not show it as written.
    """
    value = details.get(key)
    if value is None:
        return ''
    if not isinstance(value, str) or not _one_line(value):
        return None
    return value.replace('"', '')


def _quoted(text: str) -> str:
    return f'"{text}"' if text else ''


def _addresses(values):
    """Bare addresses from raw header values, or None when any entry is more than one plain address."""
    addresses = []
    for value in values:
        parsed = getaddresses([value])
        # Display names, groups and comments would be sent unseen.
        if not parsed or [raw for _name, raw in parsed] != [entry.strip() for entry in value.split(',')]:
            return None
        for _name, raw in parsed:
            if (not raw.isascii() or not _one_line(raw) or '@' not in raw
                    or any(character in ' "<>()' for character in raw)):
                return None
            addresses.append(raw)
    return addresses


def _from_line(values):
    """One 'Plain Name <address>' From value exactly as written, or None."""
    if len(values) != 1:
        return None
    match = _PLAIN_FROM.fullmatch(values[0])
    if match is None or '  ' in match.group(1) or _addresses([match.group(2)]) != [match.group(2)]:
        return None
    return [values[0]]


def _recipient_lines(headers):
    """'From:', 'Bcc:', 'Cc:', 'To:' lines in that order, or None when they cannot be shown exactly."""
    lines = []
    for label, key in (('From', 'from'), ('Bcc', 'bcc'), ('Cc', 'cc'), ('To', 'to')):
        values = headers.get(key, [])
        addresses = (key == 'from' and _from_line(values)) or _addresses(values)
        if addresses is None:
            return None
        if addresses:
            lines.append(f'{label}: {", ".join(addresses)}')
    return lines if any(not line.startswith('From:') for line in lines) else None


def _header_value_ok(name: str, value: str) -> bool:
    """Headers the text does not show must carry nothing beyond their standard form."""
    if name == 'date':
        try:
            return format_datetime(parsedate_to_datetime(value)) == value
        except (TypeError, ValueError):
            return False
    if name == 'message-id':
        return _GMAIL_MESSAGE_ID.fullmatch(value) is not None
    if name == 'received':
        match = _GMAIL_RECEIVED.fullmatch(value)
        return match is not None and _header_value_ok('date', match.group(1))
    if name == 'mime-version':
        return value == '1.0'
    if name == 'content-type':
        return _TEXT_PLAIN.fullmatch(value) is not None
    if name == 'content-transfer-encoding':
        return value.lower() in _TRANSFER_ENCODINGS
    # Shown fields; their raw values are checked where they are displayed.
    return name in ('from', 'to', 'cc', 'bcc', 'subject')


def _raw_headers(details):
    """{name: [raw values]} when every header is allowed and unshown ones are standard, else None."""
    headers = details.get('headers')
    if not isinstance(headers, list):
        return None
    values = {}
    for pair in headers:
        if not (isinstance(pair, list) and len(pair) == 2 and all(isinstance(item, str) for item in pair)):
            return None
        name, value = pair
        if (name in values and name not in _REPEATABLE_HEADERS) or not _header_value_ok(name, value):
            return None
        values.setdefault(name, []).append(value)
    return values


def _raw_subject(headers):
    """The subject exactly as sent, quotes dropped; None when encoded or not plainly shown."""
    subject = headers.get('subject', [''])[0]
    if subject and ('=?' in subject or not _one_line(subject)):
        return None
    return subject.replace('"', '')


def _email_body(details):
    """The email's only text as lines, when the approval text can show all of it, else None."""
    if (details.get('content_type') != 'text/plain' or details.get('strict_encoding') is not True
            or details.get('attachments') != [] or details.get('reply_to') != []):
        return None
    parts = details.get('parts')
    if parts == []:
        return []
    if not isinstance(parts, list) or len(parts) != 1:
        return None
    part = parts[0]
    if not isinstance(part, dict) or part.get('type') != 'text/plain' or not isinstance(part.get('content'), str):
        return None
    return _body_lines(part['content'])


def _summary(head, body):
    """Trusted lines, then body lines marked '> ' so agent text cannot pose as them. None means too long."""
    if len('\n'.join(head)) > SUMMARY_LIMIT or len('\n'.join(body)) > BODY_LIMIT:
        return None
    if body:
        head = head + ['Body:'] + [f'> {line}' if line else '>' for line in body]
    return '\n'.join(head)


def _github_names_plain(details) -> bool:
    """Owner and repo are agent-supplied and only loosely validated upstream, so show only plain names."""
    return all(isinstance(details.get(key), str) and _PLAIN_GITHUB_NAME.fullmatch(details[key])
               for key in ('owner', 'repo'))


def _dashboard_text(agent) -> str:
    return f'AgentGate approval needed from {agent}: open the AgentGate dashboard to review it.'


def _coded_text(agent, what, summary, code) -> str:
    summary_part = f'{summary}\n' if summary else ''
    return f'AgentGate approval: {agent} wants {what}.\n{summary_part}Reply "approve {code}" or "deny {code}".'


def announcement(pending, agent: str) -> tuple[str, bool]:
    """(text, approvable) for a pending request from the named agent."""
    code = pending.approval_code
    if pending.credential in READ_PERMISSIONS:
        return _coded_text(agent, f'to read {READ_PERMISSIONS[pending.credential]}', '', code), True
    details = _details(pending)
    if details is None:
        return _dashboard_text(agent), False
    if pending.credential == EMAIL_SEND:
        headers = _raw_headers(details)
        if headers is None:
            return _dashboard_text(agent), False
        recipients, subject, body = _recipient_lines(headers), _raw_subject(headers), _email_body(details)
        if recipients is None or subject is None or body is None:
            return _dashboard_text(agent), False
        head = recipients + ([f'Subject: {_quoted(subject)}'] if subject else [])
    elif pending.credential == GITHUB_WRITE and _github_names_plain(details):
        title = _field(details, 'title')
        body = _body_lines(details['body']) if isinstance(details.get('body'), str) else None
        if not title or body is None:
            return _dashboard_text(agent), False
        head = [f'Repo: {details["owner"]}/{details["repo"]}', f'Title: {_quoted(title)}']
    else:
        return _dashboard_text(agent), False
    summary = _summary(head, body)
    if summary is None:
        return f'AgentGate approval needed from {agent}: too long to review by text — open the AgentGate dashboard.', False
    return _coded_text(agent, pending.credential, summary, code), True
