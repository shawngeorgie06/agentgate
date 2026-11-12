"""iMessage assistant using policy-checked reads and explicitly requested reply drafts.

A draft request may span several texts: the assistant remembers the email and the wording
gathered so far, in memory only, until the draft is saved, cancelled, or left idle.
"""
from __future__ import annotations

import datetime as dt
import re
import json
import unicodedata
from html.parser import HTMLParser
from email.utils import getaddresses, parsedate_to_datetime

PROMPT_LIMIT = 2000
HISTORY_LIMIT = 2000
STYLE_LIMIT = 500
CONTEXT_LIMIT = 6000
REPLY_LIMIT = 1200
MESSAGE_LIMIT = 3
ISSUE_LIMIT = 10
REPO_LIMIT = 20
BODY_LIMIT = 1200
HTML_SOURCE_LIMIT = 100000
FILE_LIMIT = 4000
QUERY_LIMIT = 200
PATH_LIMIT = 500
REF_LIMIT = 255

READ_ACTIONS = frozenset({
    'chat', 'unsupported', 'gmail_unread', 'gmail_search', 'gmail_read',
    'github_repos', 'github_issues', 'github_file',
})
ACTIONS = READ_ACTIONS | {'gmail_reply_draft'}
DRAFT_COMMAND = re.compile(r'^(?:(?:please|pls|can\s+you|could\s+you|can\s+u)\s+)*(?:draft|compose|write)\s+(?:me\s+)?'
                           r'(?:an?\s+)?(?:quick\s+|short\s+)?(?:reply|response)\b', re.IGNORECASE)
DRAFT_TTL = dt.timedelta(minutes=15)
DRAFT_WORD_LIMIT = 8
DRAFT_RELAX_STEPS = 3
DRAFT_CANCEL = re.compile(r'\s*(?:cancel|stop|never\s?mind|nvm|forget\s+it)(?:\s+(?:it|that|this|the\s+draft|draft))?[\s.!]*', re.IGNORECASE)
DRAFT_YES = re.compile(r"\s*(?:yes|yep|yeah|yup|y|ok|okay|correct|right|sure|that\s+one|use\s+it|that's\s+it)[\s.!]*", re.IGNORECASE)
# Wording that starts the reply's content when the model cannot split the request.
_SAYING = re.compile(r'\b(?:saying|say|that\s+says|telling|tell\s+(?:them|him|her))\b', re.IGNORECASE)
# A model "content" answer that begins like this describes the email, not the reply.
_TOPIC = re.compile(r'\s*(?:regarding|about|concerning|re:|titled|called|with\s+(?:the\s+)?subject|from)\b', re.IGNORECASE)
_WORD = re.compile(r'[^\W_][\w.%+@-]*')
# Words that never identify an email. Everything else the user typed is searched as a keyword.
_FILLER = frozenset("""
a about address all also am an and any are as at be been but by called can concerning could dated did do does draft
compose write reply response respond email emails e-mail mail message messages msg for from get got had has have he
her him his i if im in inbox is it its just last latest like make me most my need needs new newest of on one or
please pls re received receive recent recently regarding sender sent she so some something smt subject that the
their them there they this titled to u up use was we were what which who will with would you your yesterday today
no nope not wrong different other another say saying says tell telling
""".split())

_MONTH = (r'(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?'
          r'|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)')
_MONTHS = {name: number for number, name in enumerate(
    ('jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'), 1)}
_WEEKDAYS = ('monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday')
_MONTH_DAY = re.compile(rf'\b{_MONTH}\.?\s+(\d{{1,2}})(?:st|nd|rd|th)?\b(?:,?\s+(\d{{4}})\b)?', re.IGNORECASE)
_DAY_MONTH = re.compile(rf'\b(\d{{1,2}})(?:st|nd|rd|th)?\s+(?:of\s+)?{_MONTH}\b\.?(?:,?\s+(\d{{4}})\b)?', re.IGNORECASE)
_NUMERIC_DATE = re.compile(r'(?<![\d/])(\d{1,2})/(\d{1,2})(?:/(\d{4}|\d{2}))?(?![\d/])')
_RELATIVE_DAY = re.compile(r'\b(today|yesterday)\b', re.IGNORECASE)
_WEEKDAY = re.compile(rf'\b(?:on|last|this\s+past)\s+({"|".join(_WEEKDAYS)})\b', re.IGNORECASE)
_WEEK = re.compile(r'\b(this|last)\s+week\b', re.IGNORECASE)
_DATE_PATTERNS = (_MONTH_DAY, _DAY_MONTH, _NUMERIC_DATE, _RELATIVE_DAY, _WEEKDAY, _WEEK)

PLAN_FIELDS = frozenset({'action', 'query', 'message_id', 'owner', 'repo', 'path', 'ref'})

_OWNER = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})')
_REPO = re.compile(r'[A-Za-z0-9._-]{1,100}')
_MESSAGE_ID = re.compile(r'[A-Za-z0-9_-]{1,64}')
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
# 'approve <code>' or 'deny <code>' typed in the paired self-chat. Shared with the approval reply handler.
APPROVAL_REPLY = re.compile(r'\s*(approve|deny)\s+([0-9a-fA-F]{6})\s*', re.IGNORECASE)

CAPABILITIES_MESSAGE = ('I can read accounts and draft email replies, such as checking unread email, '
                     'searching email, or reading GitHub repos, issues, and files. Sending must be initiated and approved in AgentGate.')
MALFORMED_MESSAGE = 'I could not understand that request. Please rephrase it with more detail.'
INACTIVE_MESSAGE = 'This agent identity is inactive, so I can\'t access accounts for this request.'
UNABLE_MESSAGE = 'I was unable to complete that read request, so there is nothing to summarize.'
MODEL_FAILED_MESSAGE = 'The local model could not complete this request.'
FALLBACK_MESSAGE = 'I could not produce a reply for that request.'
NO_RESULTS = 'No matching items were found.'
DRAFT_START_MESSAGE = 'To create a draft, start with “Draft a reply” and identify the email and what to say.'
DRAFT_ASK_EMAIL = ('Which email should I reply to? Tell me the sender or subject, and a date if it helps. '
                   'Text “cancel” to stop.')
DRAFT_NO_MATCH = ('No matching email found. Tell me the sender or subject, and a date if it helps. '
                  'Text “cancel” to stop.')
DRAFT_OPEN = '\nYour next text continues this draft. Text “cancel” to stop.'
DRAFT_WAITING = '\n\nYour reply draft is still open. Your next text continues it. Text “cancel” to stop.'
DRAFT_CANCELLED = 'Okay, I stopped that draft. Nothing was created.'
DRAFT_UNREADABLE = 'I could not read the email body, so I did not create a draft.'
DRAFT_FAILED = 'I could not prepare the reply. No draft was created. Check read access and try a more specific request.'
DRAFT_TOO_LONG = 'That request is too long to draft from. No draft was created. Start again with “Draft a reply”.'

# Notes handed to the model in place of result data, so it can word the reply itself.
# The fixed messages above are used only when the model cannot answer.
REFUSAL_NOTE = ('AgentGate ran nothing for this request. This iMessage assistant can read accounts and create explicitly requested email reply drafts: '
                'it can check unread Gmail, search and read Gmail messages, list GitHub repos, '
                'list open issues, and read repository files. It can draft a reply when the user starts with Draft a reply. It cannot send email, create issues, edit, '
                'delete data, or change permissions. Explain the supported capabilities to the user.')
MALFORMED_NOTE = ('AgentGate could not tell exactly what to look up from that request. Ask the user '
                  'for the missing detail, such as what to search for or the repository owner and name.')
FAILURE_NOTE = ('AgentGate tried to look this up but the read did not succeed, so no data was retrieved. '
                'This agent may not have permission for it, or the service may be unavailable.')


# Plans that mean the user moved on to another lookup instead of continuing a pending draft.
_OTHER_LOOKUPS = frozenset({'gmail_unread', 'gmail_read', 'github_repos', 'github_issues', 'github_file'})
_OTHER_REQUESTS = {'email': _OTHER_LOOKUPS, 'confirm': _OTHER_LOOKUPS | {'gmail_search'},
                   'content': _OTHER_LOOKUPS | {'gmail_search'}}
# Texts that address the assistant about the user's own accounts, or about itself, whatever the model plans for
# them. Reply wording speaks to the recipient, so it does not open with a lookup of "my" email or repos.
_ASIDE_LEAD = (r'\s*(?:(?:ok(?:ay)?|actually|never\s?mind|wait|hold on|first|also|and|hey|please)[,.!]?\s+)*'
               r'(?:(?:can|could|would|will) you\s+)?(?:please\s+)?')
_ASIDE_VERB = r'(?:list|show(?: me)?|check|search|read|open|find|get(?! back)|give me|look (?:up|at|in|through)|summari[sz]e|count)'
_ASIDE_MAIL = r'(?:e-?mails?|inbox|mail|gmail|messages)'
_ASIDE_CODE = r'(?:github|repos?|repositor(?:y|ies)|issues|pull requests|prs)'
_OTHER_REQUEST = re.compile(_ASIDE_LEAD + '(?:' + '|'.join((
    # "check my unread email", "list my GitHub repos"
    # A verb aimed at one email describes the email to reply to: "find the email from GitHub about my repos".
    rf'{_ASIDE_VERB}\b(?!\s+(?:for\s+)?(?:the|that|this|an?)\s+(?:e-?mail|message|one|thread)\b)[^.!?\n]*\bmy\s+(?:[\w-]+\s+){{0,2}}(?:{_ASIDE_MAIL}|{_ASIDE_CODE})\b',
    # "read the README in owner/repo", "list open issues in owner/repo"
    rf'{_ASIDE_VERB}\b[^.!?\n]*\b(?:readme|issues|repo|repository|file|prs|pull requests)\b[^!?\n]*'
    r'(?<![\w/.-])[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]*[A-Za-z0-9](?![\w/-])',
    rf'(?:how many|what|which)\b[^.!?\n]*\b(?:{_ASIDE_MAIL}|{_ASIDE_CODE})\b[^.!?\n]*'
    r'\b(?:do i (?:have|own)|have i got)\b(?!\s+to\b)',
    rf'how many (?:unread|new)\s+{_ASIDE_MAIL}\b',
    rf'(?:do i have|have i got)\b[^.!?\n]*\b(?:unread|{_ASIDE_MAIL}|repos?|repositories)\b',
    rf'any (?:new|unread)\s+{_ASIDE_MAIL}\b',
    rf'(?:what|which)(?: is|\'s|’s| are)\b[^.!?\n]*\bmy\s+(?:[\w-]+\s+){{0,2}}(?:{_ASIDE_MAIL}|{_ASIDE_CODE})\b',
    r'(?:what can you do(?: for me)?|what are your (?:commands|capabilities)|help)\s*[.!?]*\s*$',
)) + ')', re.IGNORECASE)


class _Malformed(Exception):
    pass


# Words too common to show that a sentence of a generated reply came from the user's request.
_COMMON = frozenset("""
a about also am an and are as at be been being but by can could did do does draft email for from had has have he
her here him his how i id if ill im in into is it its ive just let may me might mine must my no not of on or our
please reply replying said say saying says shall she should so than that the their them then there these they this
those to too us very was we were what when where which who will with would write you your yours
tell telling ask asking know
cannot cant dont doesnt didnt wont wouldnt couldnt shouldnt isnt arent wasnt werent havent hasnt hadnt
""".split())
# A sentence ends at a full stop followed by a capital or digit, so "3 p.m. on Friday" stays whole, or at a blank
# line. A single line break is only wrapping.
_SENTENCE_END = re.compile(r'((?<=[.!?])\s+(?=[^a-z\s])|\s*\n\s*\n\s*)')
_GREETING = re.compile(r'(?:hi|hello|hey|dear)(?:\s+[^\s,.!?]+){0,3}[,.!]?', re.IGNORECASE)
# A sentence that opens with one of these qualifies the sentence before it.
_CONTINUES = re.compile(r'(?:but|and|or|so|unless|however|otherwise|because|if|except|although|though|also)\b',
                        re.IGNORECASE)


def _forms(word) -> set:
    """Spellings shared by the forms of a word, so submit, submitted and submitting have one in common."""
    for suffix, ending in (('ies', 'y'), ('ing', ''), ('ed', ''), ('es', ''), ('s', '')):
        if word.endswith(suffix) and len(word) - len(suffix) >= 3:
            stem = word[:-len(suffix)] + ending
            if len(stem) > 3 and stem[-1] == stem[-2]:
                stem = stem[:-1]
            # Closed, closing and closes come from close, not clos.
            return {stem, stem + 'e'} if suffix in ('ing', 'ed', 'es') else {stem}
    return {word}


def _content_words(text) -> set:
    words = re.findall(r'[^\W_]+', re.sub(r"['’]", '', text.lower()))
    return {form for word in words if word not in _COMMON for form in _forms(word)}


def _only_requested(body, said) -> str:
    """`body` without the sentences that carry none of the words in `said`, the reply wording the user gave:
    thanks, closings and offers nobody asked for.

    A sentence made only of common words, such as "I cannot.", cannot be judged and is kept. One that qualifies a
    requested sentence before it is kept with it. A reply that carries none of the user's words anywhere is
    returned whole; the user described the reply instead of wording it.
    """
    asked = _content_words(said)
    pieces = _SENTENCE_END.split(body.strip())
    units = []      # [text, the gap after it, its content words]
    for sentence, gap in zip(pieces[::2], pieces[1::2] + ['']):
        words = _content_words(sentence)
        # Padding is not carried along by a requested sentence that happens to follow it.
        if units and words and units[-1][2] & asked and _CONTINUES.match(sentence):
            units[-1][0] += units[-1][1] + sentence
            units[-1][1] = gap
            units[-1][2] |= words
        else:
            units.append([sentence, gap, words])
    if not any(words & asked for _, _, words in units):
        return body
    return ''.join(text + gap for index, (text, gap, words) in enumerate(units)
                   if not words or words & asked or index == 0 and _GREETING.fullmatch(text)).strip()


class _Inactive(Exception):
    pass


class _ToolFailed(Exception):
    pass


def _bounded(value, limit: int) -> str:
    return value[:limit] if isinstance(value, str) else ''


def _active(identity_guard) -> bool:
    if not callable(identity_guard):
        return False
    try:
        return bool(identity_guard())
    except Exception:
        return False


def _field(plan: dict, name: str, *, required: bool = False, limit: int, pattern=None):
    value = plan.get(name, '')
    if not isinstance(value, str):
        raise _Malformed(name)
    if value == '':
        if required:
            raise _Malformed(name)
        return None
    if len(value) > limit or _CONTROL.search(value):
        raise _Malformed(name)
    if pattern is not None and not pattern.fullmatch(value):
        raise _Malformed(name)
    if value in ('.', '..'):
        raise _Malformed(name)
    return value


def _path(value: str) -> str:
    if len(value) > PATH_LIMIT or _CONTROL.search(value) or '\\' in value or value.startswith('/'):
        raise _Malformed('path')
    if any(part in ('', '.', '..') for part in value.split('/')):
        raise _Malformed('path')
    return value


def _parse_args(action: str, plan: dict) -> dict:
    if set(plan) - PLAN_FIELDS:
        raise _Malformed('unexpected field')
    if action in ('gmail_search', 'gmail_reply_draft'):
        return {'query': _field(plan, 'query', required=True, limit=QUERY_LIMIT)}
    if action == 'gmail_read':
        return {'message_id': _field(plan, 'message_id', required=True, limit=64, pattern=_MESSAGE_ID)}
    if action == 'github_issues':
        return {'owner': _field(plan, 'owner', required=True, limit=39, pattern=_OWNER),
                'repo': _field(plan, 'repo', required=True, limit=100, pattern=_REPO)}
    if action == 'github_file':
        path = _field(plan, 'path', required=True, limit=PATH_LIMIT)
        _path(path)
        return {'owner': _field(plan, 'owner', required=True, limit=39, pattern=_OWNER),
                'repo': _field(plan, 'repo', required=True, limit=100, pattern=_REPO),
                'path': path,
                'ref': _field(plan, 'ref', limit=REF_LIMIT)}
    # chat, unsupported, gmail_unread, github_repos: no arguments are used.
    for name in ('query', 'message_id', 'owner', 'repo', 'path', 'ref'):
        _field(plan, name, limit=2000)
    return {}


def _text(value, limit: int) -> str:
    if isinstance(value, list):
        value = ', '.join(item for item in value if isinstance(item, str))
    if not isinstance(value, str):
        return ''
    return value[:limit]


class _EmailHTMLText(HTMLParser):
    """Extract readable text locally, without loading links, images, or scripts."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.ignored = []

    def handle_starttag(self, tag, attrs):
        if tag == 'body' and self.ignored == ['head']:
            self.ignored.clear()
        if tag in ('head', 'script', 'style', 'template'):
            self.ignored.append(tag)
        elif not self.ignored and tag in ('br', 'p', 'div', 'li', 'tr', 'td', 'th', 'h1', 'h2', 'h3'):
            self.text.append('\n')

    def handle_endtag(self, tag):
        if self.ignored:
            if tag == self.ignored[-1]:
                self.ignored.pop()
        elif tag in ('p', 'div', 'li', 'tr', 'td', 'th', 'h1', 'h2', 'h3'):
            self.text.append('\n')

    def handle_data(self, text):
        if not self.ignored:
            self.text.append(text)


def _message_body(data):
    body = data.get('text')
    if isinstance(body, str) and body.strip():
        return body[:HTML_SOURCE_LIMIT], len(body) > HTML_SOURCE_LIMIT
    parts = data.get('parts')
    parts = parts if isinstance(parts, list) else []
    for content_type in ('text/plain', 'text/html'):
        for part in parts:
            if not isinstance(part, dict) or part.get('type') != content_type:
                continue
            content = part.get('content')
            if not isinstance(content, str) or not content.strip():
                continue
            if content_type == 'text/plain':
                return content[:HTML_SOURCE_LIMIT], len(content) > HTML_SOURCE_LIMIT
            parser = _EmailHTMLText()
            parser.feed(content[:HTML_SOURCE_LIMIT])
            parser.close()
            text = ''.join(parser.text)
            if text.strip():
                return text, len(content) > HTML_SOURCE_LIMIT
    return '', False


def _message_data(data):
    if not isinstance(data, dict):
        return None
    body, source_truncated = _message_body(data)
    body = ''.join(character for character in body
                   if unicodedata.category(character) != 'Cf' and character != '\u034f')
    lines = [' '.join(_CONTROL.sub(' ', line).split()) for line in body.splitlines()]
    body = '\n'.join(line for line in lines if line)
    raw_sender = _CONTROL.sub(' ', _text(data.get('from'), 200)).strip()
    addresses = getaddresses([raw_sender])
    sender = (', '.join(name or address for name, address in addresses) or raw_sender) if '@' in raw_sender else raw_sender
    source = 'github' if len(addresses) == 1 and addresses[0][1].lower() == 'notifications@github.com' else None
    return {'sender': sender, 'source': source,
            'date': _CONTROL.sub(' ', _text(data.get('date'), 100)).strip(),
            'subject': _CONTROL.sub(' ', _text(data.get('subject'), 200)).strip(), 'body': body[:BODY_LIMIT],
            'complete': bool(body) and len(body) <= BODY_LIMIT and not source_truncated}


def _email_context(messages, scope):
    """Keep the review envelope valid when escaping consumes the context budget."""
    review = {'kind': 'email_review', 'scope': scope, 'messages': messages}
    while True:
        text = json.dumps(review, ensure_ascii=False)
        if len(text) <= CONTEXT_LIMIT:
            return text
        longest = max(messages, key=lambda message: len(message['body']))
        if not longest['body']:
            raise _ToolFailed()
        longest['body'] = longest['body'][:max(0, len(longest['body']) - (len(text) - CONTEXT_LIMIT))]
        longest['complete'] = False


def _calendar_day(year, month, day, today):
    """The named day. Without a year it is the most recent such day that is not in the future."""
    try:
        if year is not None:
            return dt.date(year, month, day)
        value = dt.date(today.year, month, day)
        return value if value <= today else dt.date(today.year - 1, month, day)
    except ValueError:
        return None


def _day_range(text, today):
    """(first day, day after the last) for a date the user named, else None. Explicit dates win over relative ones."""
    for pattern, month_group, day_group in ((_MONTH_DAY, 1, 2), (_DAY_MONTH, 2, 1)):
        match = pattern.search(text)
        if match is not None:
            year = int(match.group(3)) if match.group(3) else None
            day = _calendar_day(year, _MONTHS[match.group(month_group)[:3].lower()], int(match.group(day_group)), today)
            if day is not None:
                return day, day + dt.timedelta(days=1)
    match = _NUMERIC_DATE.search(text)
    if match is not None:
        year = int(match.group(3)) if match.group(3) else None
        if year is not None and year < 100:
            year += 2000
        day = _calendar_day(year, int(match.group(1)), int(match.group(2)), today)
        if day is not None:
            return day, day + dt.timedelta(days=1)
    match = _RELATIVE_DAY.search(text)
    if match is not None:
        day = today if match.group(1).lower() == 'today' else today - dt.timedelta(days=1)
        return day, day + dt.timedelta(days=1)
    match = _WEEKDAY.search(text)
    if match is not None:
        back = (today.weekday() - _WEEKDAYS.index(match.group(1).lower())) % 7 or 7
        day = today - dt.timedelta(days=back)
        return day, day + dt.timedelta(days=1)
    match = _WEEK.search(text)
    if match is not None:
        monday = today - dt.timedelta(days=today.weekday())
        if match.group(1).lower() == 'this':
            return monday, today + dt.timedelta(days=1)
        return monday - dt.timedelta(days=7), monday
    return None


def _email_words(text):
    """(keywords, all kept) from the user's own words that identify an email. Never Gmail operators."""
    for pattern in _DATE_PATTERNS:
        text = pattern.sub(' ', text)
    words = []
    for token in _WORD.findall(text):
        word = token.rstrip('.%+@-').lower()
        if len(word) < 2 or word in _FILLER or word in words:
            continue
        words.append(word)
    return words[:DRAFT_WORD_LIMIT], len(words) <= DRAFT_WORD_LIMIT


def _day_start(day, zone):
    """Epoch second at which a local day starts. Without a zone, the Mac's zone and its daylight-saving rules."""
    return int(dt.datetime.combine(day, dt.time.min, tzinfo=zone).timestamp())


def _email_label(message, zone):
    """Sender, subject, and day of an email, for telling the user which one was picked."""
    sender = message['sender'][:80] or 'unknown sender'
    subject = message['subject'][:120] or 'no subject'
    label = f'{sender} — “{subject}”'
    try:
        received = parsedate_to_datetime(message['date'])
        if received.tzinfo is not None:
            received = received.astimezone(zone)
        label += f' ({received.strftime("%b")} {received.day})'
    except (TypeError, ValueError, OverflowError):
        pass
    return label


class _PendingDraft:
    """One reply draft being gathered over several texts. Memory only, never saved."""

    def __init__(self, agent):
        self.agent = agent
        self.stage = 'email'      # 'email': which email; 'confirm': is this the one; 'content': what to say
        self.content = []         # the user's texts that say what the reply should say
        self.said = []            # only their reply wording, without the part that names the email
        self.days = None
        self.message_id = None
        self.candidate = None
        self.several = False
        self.expires = None


def _clean_reply(answer) -> str:
    text = answer.strip() if isinstance(answer, str) else ''
    # A reply sent from the self-chat would read back as an approval decision, so never send one.
    if not text or text.lower().startswith('/agent') or APPROVAL_REPLY.fullmatch(text):
        return FALLBACK_MESSAGE
    return text[:REPLY_LIMIT]


class MessageAgent:
    def __init__(self, audit, gmail_tools, github_tools, model, clock=None, zone=None):
        self._audit = audit
        self._gmail = gmail_tools
        self._github = github_tools
        self._model = model
        self._clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        # Days such as "yesterday" are the user's days: this zone, or the Mac's own when None.
        self._zone = zone
        self._draft = None

    def forget(self):
        """Drop a draft request that is still being gathered."""
        self._draft = None

    async def reply(self, agent_name: str, identity_guard, prompt: str, history: str = '',
                    style: str = '') -> str:
        text, decision, action = await self._run(agent_name, identity_guard, prompt, history, style)
        if not _active(identity_guard):
            self._draft = None
        if self._audit is not None:
            label = action if action in ACTIONS else 'invalid'
            self._audit.log(agent=agent_name, credential_requested=f'imessage:{label}',
                            policy_matched='message-assistant', decision=decision, mode='message-assistant',
                            token_expiry=None)
        return text

    async def _run(self, agent_name, identity_guard, prompt, history, style):
        prompt = _bounded(prompt, PROMPT_LIMIT)
        history = _bounded(history, HISTORY_LIMIT)
        style = _bounded(style, STYLE_LIMIT)
        now = self._clock()
        draft = self._draft
        if draft is not None and (draft.agent != agent_name or now >= draft.expires):
            draft = self._draft = None
        if DRAFT_COMMAND.match(prompt.strip()):
            if not _active(identity_guard):
                self._draft = None
                return INACTIVE_MESSAGE, 'denied', 'gmail_reply_draft'
            self._draft = _PendingDraft(agent_name)
            return (*await self._draft_turn(agent_name, identity_guard, prompt, now), 'gmail_reply_draft')
        if draft is not None and DRAFT_CANCEL.fullmatch(prompt):
            self._draft = None
            return DRAFT_CANCELLED, 'completed', 'gmail_reply_draft'
        try:
            plan = await self._model.plan(prompt, history)
        except Exception:
            return MODEL_FAILED_MESSAGE, 'failed', None
        if not _active(identity_guard):
            self._draft = None
            return INACTIVE_MESSAGE, 'denied', None
        if not isinstance(plan, dict) or not isinstance(plan.get('action'), str):
            return MALFORMED_MESSAGE, 'denied', None
        action = plan['action']
        # While a draft is being gathered, the next text continues it unless it is clearly another request.
        if draft is not None:
            if action not in _OTHER_REQUESTS[draft.stage] and not _OTHER_REQUEST.match(prompt):
                return (*await self._draft_turn(agent_name, identity_guard, prompt, now), 'gmail_reply_draft')
            text, decision, action = await self._answer(agent_name, identity_guard, prompt, history, style, plan)
            # The draft stepped aside for this text, so say that it is still waiting.
            waiting = self._draft is draft and self._clock() < draft.expires and _active(identity_guard)
            return text + DRAFT_WAITING if waiting else text, decision, action
        return await self._answer(agent_name, identity_guard, prompt, history, style, plan)

    async def _answer(self, agent_name, identity_guard, prompt, history, style, plan):
        """Answer a request that is not part of a draft."""
        action = plan['action']
        if action not in ACTIONS:
            return await self._say(prompt, REFUSAL_NOTE, history, style, CAPABILITIES_MESSAGE), 'denied', None
        try:
            args = _parse_args(action, plan)
        except _Malformed:
            return await self._say(prompt, MALFORMED_NOTE, history, style, MALFORMED_MESSAGE), 'denied', action
        if action == 'gmail_reply_draft':
            # Only the user's own "Draft a reply" text starts a draft; the model's plan never does.
            return DRAFT_START_MESSAGE, 'denied', action
        if action == 'unsupported':
            return await self._say(prompt, REFUSAL_NOTE, history, style, CAPABILITIES_MESSAGE), 'completed', action

        try:
            context = await self._gather(action, args, agent_name, identity_guard)
        except _Inactive:
            return INACTIVE_MESSAGE, 'denied', action
        except Exception:
            if not _active(identity_guard):
                return INACTIVE_MESSAGE, 'denied', action
            return await self._say(prompt, FAILURE_NOTE, history, style, UNABLE_MESSAGE), 'failed', action

        if not _active(identity_guard):
            return INACTIVE_MESSAGE, 'denied', action
        try:
            answer = await self._model.answer(prompt, context, history, style)
        except Exception:
            return MODEL_FAILED_MESSAGE, 'failed', action
        return _clean_reply(answer), 'completed', action

    async def _draft_turn(self, agent, guard, prompt, now):
        """Advance the pending draft with one text from the user."""
        draft = self._draft
        draft.expires = now + DRAFT_TTL
        message = None
        try:
            if draft.stage == 'confirm':
                if DRAFT_YES.fullmatch(prompt):
                    draft.message_id, draft.candidate, draft.stage = draft.candidate, None, 'content'
                else:
                    draft.candidate, draft.stage = None, 'email'
            elif draft.stage == 'content':
                draft.content.append(prompt)
                draft.said.append(prompt)
            if draft.message_id is None:
                # Once the wording is known, a follow-up text can only be naming the email.
                which = prompt if draft.content else await self._split_request(prompt, draft)
                days = _day_range(which, now.astimezone(self._zone).date())
                words, complete = _email_words(which)
                if not words and days is None:
                    return DRAFT_ASK_EMAIL, 'completed'
                draft.days = days or draft.days
                found = await self._find_email(agent, guard, words, draft.days)
                if found is None:
                    return DRAFT_NO_MATCH, 'completed'
                message_id, exact, draft.several = found
                message = await self._read_email(agent, guard, message_id)
                if message is None:
                    self._draft = None
                    return DRAFT_UNREADABLE, 'failed'
                # A match on only some of the user's words might be a different email.
                if not exact or not complete:
                    draft.candidate, draft.stage = message_id, 'confirm'
                    return (f'I did not find an exact match. Closest: {_email_label(message, self._zone)}.\n'
                            'Text “yes” to reply to it, or tell me the sender or subject.'), 'completed'
                draft.message_id, draft.stage = message_id, 'content'
            if message is None:
                message = await self._read_email(agent, guard, draft.message_id)
                if message is None:
                    self._draft = None
                    return DRAFT_UNREADABLE, 'failed'
            if not draft.content:
                several = ' It is the newest of several matches.' if draft.several else ''
                return (f'Replying to {_email_label(message, self._zone)}.{several}\n'
                        'What should the reply say? Text “cancel” to stop.'), 'completed'
            body = await self._write_reply(guard, draft, message)
        except _Inactive:
            self._draft = None
            return INACTIVE_MESSAGE, 'denied'
        except Exception:
            self._draft = None
            return DRAFT_FAILED, 'failed'
        if not isinstance(body, str):
            return body
        self._draft = None
        return await self._save_draft(agent, guard, draft, body)

    async def _split_request(self, prompt, draft):
        """Record whether this text says what to reply, and return the part that says which email."""
        said = ''
        try:
            result = await self._model.draft_request(prompt)
            reply = result.get('reply') if isinstance(result, dict) else None
            if isinstance(reply, str) and len(reply) <= 1000 and not _TOPIC.match(reply):
                said = reply.strip()
        except Exception:
            pass
        # Wording the user did not type is the model's invention, not something to reply with.
        # The same words earlier in the text describe the email; the wording follows the saying marker.
        marker = _SAYING.search(prompt)
        index = prompt.lower().find(said.lower(), marker.end() if marker else 0) if said else -1
        if index < 0:
            if marker is None or not prompt[marker.end():].strip():
                return prompt
            index = marker.start()
        draft.content.append(prompt)
        draft.said.append(prompt[index:])
        return prompt[:index]

    async def _find_email(self, agent, guard, words, days):
        """(message id, exact, several) for the newest matching email, else None.

        The user's keywords must all match first, in the sender or subject before anywhere. If nothing does, trailing keywords and then the date
        are dropped; such a looser match is not exact and needs the user's confirmation.
        """
        attempts = [(words, days)]
        attempts += [(words[:-cut], days) for cut in range(1, DRAFT_RELAX_STEPS + 1) if len(words) > cut]
        if days is not None and words:
            attempts.append((words, None))
        for index, (terms, period) in enumerate(attempts):
            dated = []
            if period is not None:
                first, after_last = (_day_start(day, self._zone) for day in period)
                dated = [f'after:{first - 1}', f'before:{after_last}']
            # An email whose sender or subject has the words beats a newer one that only mentions them.
            searches = [[f'{{from:{term} subject:{term}}}' for term in terms], list(terms)] if terms else [[]]
            for parts in searches:
                listing = await self._call(self._gmail, agent, 'gmail:read', 'search', guard,
                                           query=' '.join(parts + dated + ['-in:sent', '-in:drafts']), limit=2)
                matches = listing.get('messages', []) if isinstance(listing, dict) else []
                if not matches:
                    continue
                message_id = matches[0].get('id') if isinstance(matches[0], dict) else None
                if not isinstance(message_id, str) or not _MESSAGE_ID.fullmatch(message_id):
                    raise _Malformed('message_id')
                several = len(matches) > 1 or bool(listing.get('nextPageToken'))
                # A date alone says when, not which, so it is never an exact match.
                return message_id, index == 0 and bool(words), several
        return None

    async def _read_email(self, agent, guard, message_id):
        source = await self._call(self._gmail, agent, 'gmail:read', 'read', guard, message_id=message_id)
        message = _message_data(source)
        return message if message is not None and message['body'] else None

    async def _write_reply(self, guard, draft, message):
        """The reply body, or a (text, decision) answer when no draft should be created yet."""
        prompt = '\n'.join(draft.content)
        context = json.dumps({'kind': 'email_reply_draft', 'email': message}, ensure_ascii=False)
        if len(prompt) > PROMPT_LIMIT:
            self._draft = None
            return DRAFT_TOO_LONG, 'failed'
        if len(context) > CONTEXT_LIMIT:
            self._draft = None
            return 'This email exceeds the drafting context limit. No draft was created.', 'failed'
        result = await self._model.draft_reply(prompt, context)
        if not isinstance(result, dict) or set(result) != {'body', 'clarification'}:
            raise _Malformed('draft')
        body, clarification = result['body'], result['clarification']
        if (not isinstance(body, str) or not isinstance(clarification, str)
                or len(body) > 1000 or len(clarification) > 300 or '\x00' in body + clarification
                or bool(body.strip()) == bool(clarification.strip())):
            raise _Malformed('draft')
        # The draft stays pending after these two answers, so the user's next text adds the missing detail.
        if clarification.strip():
            return 'No draft created yet. ' + clarification.strip() + DRAFT_OPEN, 'completed'
        body = _only_requested(body, '\n'.join(draft.said))
        supplied_numbers = set(re.findall(r'\d+', prompt + '\n' + message['body']))
        if not set(re.findall(r'\d+', body)).issubset(supplied_numbers):
            return ('No draft created yet. Please provide the exact numbers or dates to include; '
                    'the generated reply added details not in your request or the email.' + DRAFT_OPEN), 'completed'
        if not _active(guard):
            raise _Inactive()
        return body

    async def _save_draft(self, agent, guard, draft, body):
        message_id = draft.message_id
        try:
            result = await self._gmail.create_reply_draft(agent, message_id, body.strip(), identity_guard=guard)
        except Exception:
            return 'Draft creation could not be confirmed. Check Gmail Drafts before asking again; nothing was sent.', 'failed'
        if isinstance(result, dict) and result.get('code') == 'draft_not_created':
            reason = _CONTROL.sub(' ', _text(result.get('reason'), 300))
            return 'No draft was created: ' + reason, 'failed'
        if not isinstance(result, dict) or result.get('ok') is not True:
            return 'Draft creation was denied or could not be confirmed. Check draft permissions and Gmail Drafts before asking again. Nothing was sent.', 'failed'
        data = result.get('data', {})
        if not isinstance(data, dict) or not isinstance(data.get('id'), str):
            return 'Draft creation could not be confirmed. Check Gmail Drafts before asking again; nothing was sent.', 'failed'
        recipient = _CONTROL.sub(' ', _text(data.get('to'), 320))
        subject = _CONTROL.sub(' ', _text(data.get('subject'), 180))
        several = ' It replies to the newest of several matching emails.' if draft.several else ''
        header = f'Draft saved in Gmail, not sent.{several}\nTo: {recipient}\nSubject: {subject}\n\n'
        footer = '\n\nReview in AgentGate → Drafts. Sending requires a separate request and explicit approval in AgentGate.'
        available = REPLY_LIMIT - len(header) - len(footer)
        preview = body.strip()
        if len(preview) > available:
            preview = preview[:available - 1] + '…'
        return header + preview + footer, 'completed'

    async def _say(self, prompt, note, history, style, fallback):
        """Let the model word a reply from a fixed AgentGate note; use the fixed text if it can't."""
        try:
            answer = await self._model.answer(prompt, f'AgentGate note: {note}', history, style)
        except Exception:
            return fallback
        text = _clean_reply(answer)
        return fallback if text == FALLBACK_MESSAGE else text

    async def _gather(self, action, args, agent_name, guard) -> str:
        if action == 'chat':
            return ''
        if action in ('gmail_unread', 'gmail_search'):
            query = 'is:unread' if action == 'gmail_unread' else args['query']
            listing = await self._call(self._gmail, agent_name, 'gmail:read', 'search', guard,
                                       query=query, limit=MESSAGE_LIMIT)
            messages = listing.get('messages') if isinstance(listing, dict) else None
            ids = [m.get('id') for m in (messages or []) if isinstance(m, dict)][:MESSAGE_LIMIT]
            blocks = []
            for message_id in ids:
                if not isinstance(message_id, str) or not _MESSAGE_ID.fullmatch(message_id):
                    continue
                data = await self._call(self._gmail, agent_name, 'gmail:read', 'read', guard,
                                        message_id=message_id)
                message = _message_data(data)
                if message is not None:
                    blocks.append(message)
            if not blocks:
                return NO_RESULTS
            noun = 'message' if len(blocks) == 1 else 'messages'
            scope = f'unread {noun}' if action == 'gmail_unread' else f'matching {noun}'
            coverage = f'Checked {len(blocks)} {scope} from the first search page, not the entire inbox.'
            return _email_context(blocks, coverage)
        if action == 'gmail_read':
            data = await self._call(self._gmail, agent_name, 'gmail:read', 'read', guard,
                                    message_id=args['message_id'])
            message = _message_data(data)
            return _email_context([message], 'Checked 1 requested email.') if message is not None else NO_RESULTS
        if action == 'github_repos':
            data = await self._call(self._github, agent_name, 'github:read', 'repos', guard,
                                    per_page=REPO_LIMIT, page=1)
            lines = []
            for repo in (data if isinstance(data, list) else [])[:REPO_LIMIT]:
                if isinstance(repo, dict):
                    lines.append(f'- {_text(repo.get("full_name"), 200)}: {_text(repo.get("description"), 200)}')
            return '\n'.join(lines)[:CONTEXT_LIMIT] or NO_RESULTS
        if action == 'github_issues':
            data = await self._call(self._github, agent_name, 'github:read', 'issues', guard,
                                    owner=args['owner'], repo=args['repo'], state='open',
                                    limit=ISSUE_LIMIT, page=1)
            lines = []
            for issue in (data if isinstance(data, list) else [])[:ISSUE_LIMIT]:
                if isinstance(issue, dict):
                    number = issue.get('number') if isinstance(issue.get('number'), int) else ''
                    lines.append(f'- #{number} [{_text(issue.get("state"), 20)}] '
                                 f'{_text(issue.get("title"), 200)}: {_text(issue.get("body"), 300)}')
            return '\n'.join(lines)[:CONTEXT_LIMIT] or NO_RESULTS
        # github_file
        data = await self._call(self._github, agent_name, 'github:read', 'read_file', guard,
                                owner=args['owner'], repo=args['repo'], path=args['path'],
                                ref=args['ref'])
        if not isinstance(data, dict):
            return NO_RESULTS
        return (f'Path: {_text(data.get("path"), PATH_LIMIT)}\n'
                f'Content: {_text(data.get("content"), FILE_LIMIT)}')[:CONTEXT_LIMIT]

    async def _call(self, tools, agent_name, resource, operation, guard, **arguments):
        if not _active(guard):
            raise _Inactive()
        result = await tools.execute(agent_name, resource, operation, identity_guard=guard, **arguments)
        if not isinstance(result, dict) or result.get('ok') is not True:
            raise _ToolFailed()
        return result.get('data')
