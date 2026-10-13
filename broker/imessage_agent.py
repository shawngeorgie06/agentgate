"""Read-only iMessage agent: plan with a local model, read through AgentGate tools, reply briefly."""
from __future__ import annotations

import re

PROMPT_LIMIT = 2000
HISTORY_LIMIT = 2000
STYLE_LIMIT = 500
CONTEXT_LIMIT = 6000
REPLY_LIMIT = 1200
MESSAGE_LIMIT = 3
ISSUE_LIMIT = 10
REPO_LIMIT = 20
BODY_LIMIT = 1200
FILE_LIMIT = 4000
QUERY_LIMIT = 200
PATH_LIMIT = 500
REF_LIMIT = 255

READ_ACTIONS = frozenset({
    'chat', 'unsupported', 'gmail_unread', 'gmail_search', 'gmail_read',
    'github_repos', 'github_issues', 'github_file',
})
PLAN_FIELDS = frozenset({'action', 'query', 'message_id', 'owner', 'repo', 'path', 'ref'})

_OWNER = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})')
_REPO = re.compile(r'[A-Za-z0-9._-]{1,100}')
_MESSAGE_ID = re.compile(r'[A-Za-z0-9_-]{1,64}')
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')

READ_ONLY_MESSAGE = ('I can only do read-only requests, such as checking unread email, '
                     'searching email, or reading GitHub repos, issues, and files.')
UNSUPPORTED_MESSAGE = ('I can\'t do that yet. I can check and read email, and read GitHub '
                       'repos, issues, and files.')
MALFORMED_MESSAGE = 'I could not understand that request. Please rephrase it with more detail.'
INACTIVE_MESSAGE = 'This agent identity is inactive, so I can\'t access accounts for this request.'
UNABLE_MESSAGE = 'I was unable to complete that read request, so there is nothing to summarize.'
MODEL_FAILED_MESSAGE = 'The local model could not complete this request.'
FALLBACK_MESSAGE = 'I could not produce a reply for that request.'
NO_RESULTS = 'No matching items were found.'

# Notes handed to the model in place of result data, so it can word the reply itself.
# The fixed messages above are used only when the model cannot answer.
REFUSAL_NOTE = ('AgentGate ran nothing for this request. This iMessage assistant is read-only: '
                'it can check unread Gmail, search and read Gmail messages, list GitHub repos, '
                'list open issues, and read repository files. It cannot send, draft, create, edit, '
                'delete, or change anything. Explain this to the user.')
MALFORMED_NOTE = ('AgentGate could not tell exactly what to look up from that request. Ask the user '
                  'for the missing detail, such as what to search for or the repository owner and name.')
FAILURE_NOTE = ('AgentGate tried to look this up but the read did not succeed, so no data was retrieved. '
                'This agent may not have permission for it, or the service may be unavailable.')


class _Malformed(Exception):
    pass


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
    if action == 'gmail_search':
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


def _message_block(data) -> str:
    if not isinstance(data, dict):
        return ''
    body = data.get('text')
    if not isinstance(body, str):
        parts = data.get('parts')
        body = ''
        if isinstance(parts, list):
            body = next((p.get('content', '') for p in parts
                         if isinstance(p, dict) and p.get('type') == 'text/plain'
                         and isinstance(p.get('content'), str)), '')
    return '\n'.join([
        f'From: {_text(data.get("from"), 200)}',
        f'Date: {_text(data.get("date"), 100)}',
        f'Subject: {_text(data.get("subject"), 200)}',
        f'Body: {_text(body, BODY_LIMIT)}',
    ])


def _clean_reply(answer) -> str:
    text = answer.strip() if isinstance(answer, str) else ''
    if not text or text.lower().startswith('/agent'):
        return FALLBACK_MESSAGE
    return text[:REPLY_LIMIT]


class ReadOnlyMessageAgent:
    def __init__(self, audit, gmail_tools, github_tools, model):
        self._audit = audit
        self._gmail = gmail_tools
        self._github = github_tools
        self._model = model

    async def reply(self, agent_name: str, identity_guard, prompt: str, history: str = '',
                    style: str = '') -> str:
        text, decision, action = await self._run(agent_name, identity_guard, prompt, history, style)
        if self._audit is not None:
            label = action if action in READ_ACTIONS else 'invalid'
            self._audit.log(agent=agent_name, credential_requested=f'imessage:{label}',
                            policy_matched='read-only', decision=decision, mode='read-only',
                            token_expiry=None)
        return text

    async def _run(self, agent_name, identity_guard, prompt, history, style):
        prompt = _bounded(prompt, PROMPT_LIMIT)
        history = _bounded(history, HISTORY_LIMIT)
        style = _bounded(style, STYLE_LIMIT)
        try:
            plan = await self._model.plan(prompt, history)
        except Exception:
            return MODEL_FAILED_MESSAGE, 'failed', None
        if not _active(identity_guard):
            return INACTIVE_MESSAGE, 'denied', None
        if not isinstance(plan, dict) or not isinstance(plan.get('action'), str):
            return MALFORMED_MESSAGE, 'denied', None
        action = plan['action']
        if action not in READ_ACTIONS:
            return await self._say(prompt, REFUSAL_NOTE, history, style, READ_ONLY_MESSAGE), 'denied', None
        try:
            args = _parse_args(action, plan)
        except _Malformed:
            return await self._say(prompt, MALFORMED_NOTE, history, style, MALFORMED_MESSAGE), 'denied', action
        if action == 'unsupported':
            return await self._say(prompt, REFUSAL_NOTE, history, style, UNSUPPORTED_MESSAGE), 'completed', action

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
                blocks.append(_message_block(data))
            return '\n\n---\n\n'.join(blocks)[:CONTEXT_LIMIT] or NO_RESULTS
        if action == 'gmail_read':
            data = await self._call(self._gmail, agent_name, 'gmail:read', 'read', guard,
                                    message_id=args['message_id'])
            return _message_block(data)[:CONTEXT_LIMIT] or NO_RESULTS
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
