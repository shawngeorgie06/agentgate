"""JSON command interface for trusted local agents using the running broker."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

import httpx2 as httpx
from fastmcp import Client

from broker.config import ConfigError
from broker.http_auth import read_token_file


class AgentClientError(Exception):
    def __init__(self, reason: str, *, uncertain: bool = False):
        super().__init__(reason)
        self.uncertain = uncertain


def connection_reason(error: Exception) -> str:
    seen = set()
    current = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, httpx.ConnectError):
            return 'Cannot connect to the broker. Start it in another terminal and leave it running.'
        if isinstance(current, httpx.HTTPStatusError) and current.response.status_code in (401, 403):
            return 'Broker authentication rejected. Check that the client and broker use the same private token file.'
        current = current.__cause__ or current.__context__
    return 'Broker request failed. Check the broker terminal and authentication.'


def positive_number(value: str) -> float:
    import math
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError('must be a finite positive number')
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='AgentGate local agent commands; JSON results on stdout')
    parser.add_argument('--token-file', default='~/.config/agentgate/mcp-token')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--agent', default='agentgate-local')
    parser.add_argument('--timeout', type=positive_number, default=90, help='request timeout in seconds; allow time for terminal approval')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('status', help='check the running broker')
    search = commands.add_parser('search', help='search Gmail using Gmail query syntax')
    search.add_argument('query')
    search.add_argument('--limit', type=int, default=20)
    search.add_argument('--page-token')
    read = commands.add_parser('read', help='read a Gmail message')
    read.add_argument('message_id')
    draft = commands.add_parser('draft', help='create an unsent plain-text draft')
    draft.add_argument('--to', required=True)
    draft.add_argument('--subject', required=True)
    draft.add_argument('--cc', default='')
    draft.add_argument('--bcc', default='')
    draft.add_argument('--body-file', default='-', help='UTF-8 file, or - to read stdin (default)')
    send = commands.add_parser('send-draft', help='request a send; waits for approval in the broker terminal')
    send.add_argument('draft_id')
    return parser


async def execute(args: argparse.Namespace) -> dict:
    token = read_token_file(args.token_file)
    values = {'agent': args.agent}
    if args.command == 'status':
        tool, values = 'broker.status', {}
    elif args.command == 'search':
        tool = 'gmail.search'
        values.update(query=args.query, limit=args.limit, page_token=args.page_token)
    elif args.command == 'read':
        tool = 'gmail.read'
        values.update(message_id=args.message_id)
    elif args.command == 'draft':
        tool = 'gmail.draft'
        try:
            body = sys.stdin.read() if args.body_file == '-' else Path(args.body_file).expanduser().read_text(encoding='utf-8')
        except (OSError, UnicodeError):
            raise AgentClientError('Cannot read the draft body. Supply an existing UTF-8 file with --body-file, or provide the body on stdin.') from None
        values.update(to=args.to, subject=args.subject, cc=args.cc, bcc=args.bcc, body=body)
    else:
        tool = 'gmail.send_draft'
        values.update(draft_id=args.draft_id)
    # The address is fixed to loopback so a URL option cannot forward the token.
    dispatched = False
    try:
        async with Client(f'http://127.0.0.1:{args.port}/mcp', auth=token, timeout=args.timeout) as client:
            dispatched = True
            result = (await client.call_tool(tool, values)).data
    except Exception as exc:
        raise AgentClientError(connection_reason(exc), uncertain=dispatched) from None
    return {'ok': True, 'data': result} if args.command == 'status' else result


def run(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error('--port must be between 1 and 65535')
    if args.command == 'search' and not 1 <= args.limit <= 100:
        parser.error('--limit must be between 1 and 100')
    uncertain = False
    try:
        result = asyncio.run(execute(args))
    except AgentClientError as exc:
        uncertain = exc.uncertain
        result = {'ok': False, 'reason': str(exc)}
    except ConfigError as exc:
        result = {'ok': False, 'reason': str(exc)}
    except (OSError, UnicodeError):
        uncertain = True
        result = {'ok': False, 'reason': 'Could not read a local file or connect to the broker.'}
    except Exception:
        uncertain = True
        # Client exceptions may include authentication headers or email content.
        result = {'ok': False, 'reason': 'Broker request failed. Check the broker terminal and authentication.'}
    except KeyboardInterrupt:
        uncertain = True
        result = {'ok': False, 'reason': 'Client interrupted.'}
    if uncertain and args.command in ('draft', 'send-draft'):
        result['notice'] = 'Check Gmail and the broker terminal before another attempt. Do not automatically retry; the operation may have completed.'
    print(json.dumps(result, ensure_ascii=True))
    return 0 if result.get('ok') else 1


if __name__ == '__main__':
    raise SystemExit(run(sys.argv[1:]))
