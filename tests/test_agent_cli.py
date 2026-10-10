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


def test_missing_body_file_is_reported_before_any_request(tmp_path, capsys):
    token = tmp_path / 'token'
    create_token_file(str(token))
    assert agent.run(['--token-file', str(token), 'draft', '--to', 'recipient@example.test',
                      '--subject', 'Subject', '--body-file', str(tmp_path / 'missing.txt')]) == 1
    result = json.loads(capsys.readouterr().out)
    assert 'Cannot read the draft body' in result['reason']
    assert 'notice' not in result


@pytest.mark.parametrize('during_dispatch', [False, True])
def test_connection_errors_distinguish_startup_from_uncertain_dispatch(tmp_path, monkeypatch, capsys, during_dispatch):
    import httpx2
    token = tmp_path / 'token'
    create_token_file(str(token))
    class BrokenClient:
        async def __aenter__(self):
            if not during_dispatch:
                try:
                    raise httpx2.ConnectError('Bearer secret-token')
                except Exception as exc:
                    raise RuntimeError('Client startup failed') from exc
            return self
        async def __aexit__(self, *args):
            return None
        async def call_tool(self, *args):
            raise httpx2.ConnectError('Bearer secret-token')
    monkeypatch.setattr(agent, 'Client', lambda *args, **kwargs: BrokenClient())
    assert agent.run(['--token-file', str(token), 'send-draft', 'draft-1']) == 1
    output = capsys.readouterr().out
    result = json.loads(output)
    assert 'Cannot connect to the broker' in result['reason']
    assert ('notice' in result) is during_dispatch
    assert 'secret-token' not in output
