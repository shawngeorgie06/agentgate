import io
import json

import pytest
from fastmcp import Client, FastMCP

from broker.gmail_tools import register_gmail_tools
from broker.http_auth import create_token_file
from cli import agent
from tests.test_gmail import make_tools


@pytest.mark.asyncio
async def test_commands_use_gmail_tools_without_exporting_credentials(tmp_path, monkeypatch):
    broker, service, gmail, _ = make_tools(tmp_path)
    mcp = FastMCP('Agent commands test')
    register_gmail_tools(mcp, broker, gmail)
    path = tmp_path / 'token'
    create_token_file(str(path))
    addresses = []
    def client(url, **kwargs):
        addresses.append(url)
        assert kwargs['timeout'] == 90
        return Client(mcp)
    monkeypatch.setattr(agent, 'Client', client)
    prefix = ['--token-file', str(path), '--agent', 'local-agent']
    async def invoke(arguments):
        return await agent.execute(agent.build_parser().parse_args(prefix + arguments))
    search = await invoke(['search', 'is:unread', '--limit', '2', '--page-token', 'page-2'])
    assert search['data']['nextPageToken'] == 'next'
    assert service.calls[-1][2]['q'] == 'is:unread'
    assert service.calls[-1][2]['pageToken'] == 'page-2'
    read = await invoke(['read', 'message-1'])
    assert read['data']['parts'][0]['content'] == 'Hello!\n'
    body = tmp_path / 'body.txt'
    body.write_text('Multiline\nCafé\n')
    assert (await invoke(['draft', '--to', 'recipient@example.test', '--subject', 'Subject', '--body-file', str(body)]))['ok']
    from broker.integrations.gmail import describe_message
    created = describe_message(service.calls[-1][2]['body']['message']['raw'])
    assert created['parts'][0]['content'] == 'Multiline\nCafé\n'
    monkeypatch.setattr(agent.sys, 'stdin', io.StringIO('From stdin\n'))
    assert (await invoke(['draft', '--to', 'recipient@example.test', '--subject', 'Subject']))['ok']
    assert describe_message(service.calls[-1][2]['body']['message']['raw'])['parts'][0]['content'] == 'From stdin\n'
    assert not any(call[1] == 'send' for call in service.calls)
    assert addresses == ['http://127.0.0.1:8765/mcp'] * 4


@pytest.mark.parametrize('command', [['status'], ['draft', '--to', 'recipient@example.test', '--subject', 'Subject'], ['send-draft', 'draft-1']])
def test_failures_are_safe_json_and_never_retried(monkeypatch, capsys, command):
    calls = []
    async def failed(args):
        calls.append(args.command)
        raise RuntimeError('Bearer secret-token; private email body')
    monkeypatch.setattr(agent, 'execute', failed)
    assert agent.run(command) == 1
    output = capsys.readouterr()
    result = json.loads(output.out)
    assert result['ok'] is False
    assert not output.err
    assert 'secret-token' not in output.out
    assert 'private email body' not in output.out
    assert len(calls) == 1
    if command[0] != 'status':
        assert 'Do not automatically retry' in result['notice']


@pytest.mark.parametrize('arguments', [['--port', '0', 'status'], ['search', 'in:inbox', '--limit', '101'], ['--timeout', 'nan', 'status']])
def test_invalid_arguments_rejected_before_connection(arguments):
    with pytest.raises(SystemExit) as error:
        agent.run(arguments)
    assert error.value.code == 2
