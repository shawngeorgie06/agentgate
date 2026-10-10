import asyncio
import json
import os
import pty
import select

import pytest
from fastmcp import Client

from broker.console import console_loop, Terminal
from broker.mcp_server import build_mcp
from tests.test_main import _cfg
from broker.main import build_broker


@pytest.mark.asyncio
async def test_mcp_approval_and_denial_use_terminal(tmp_path, capsys):
    broker = build_broker(_cfg(tmp_path), 'pw')
    broker.store.store('demo-key', 'dummy-value')
    master, slave = pty.openpty()
    terminal = Terminal(slave)
    console = asyncio.create_task(console_loop(broker, terminal))
    try:
        async with Client(build_mcp(broker)) as client:
            for answer, granted in ((b'y\n', True), (b'n\n', False)):
                request = asyncio.create_task(client.call_tool(
                    'credential.request', {'agent': 'demo', 'credential': 'demo-key'}
                ))
                async with asyncio.timeout(5):
                    while broker.approvals.get_pending() is None:
                        await asyncio.sleep(0.01)
                    # Approval must appear while the operator was idle.
                    await asyncio.sleep(0.1)
                    assert select.select([master], [], [], 0)[0]
                    assert b'[y/n]' in os.read(master, 4096)
                    os.write(master, answer)
                    result = (await request).data
                assert result['granted'] is granted
                assert result['value'] == ('dummy-value' if granted else None)
        assert capsys.readouterr().out == ''
        log = open(broker.config.logs_path).read()
        assert 'dummy-value' not in log
        assert [json.loads(line)['decision'] for line in log.splitlines()] == [
            'escalated', 'approved', 'escalated', 'denied'
        ]
    finally:
        console.cancel()
        await asyncio.gather(console, return_exceptions=True)
        terminal.close()
        os.close(master)


@pytest.mark.asyncio
async def test_real_stdio_server_headless_timeout(tmp_path):
    import sys
    from pathlib import Path
    from fastmcp.client.transports import StdioTransport
    config = _cfg(tmp_path)
    broker = build_broker(config, 'pw')
    broker.store.store('demo-key', 'dummy-value')
    # MCP stdio transport launches the server in a new session.
    transport = StdioTransport(
        command=sys.executable,
        args=['-m', 'broker.main'],
        cwd=str(Path(__file__).resolve().parents[1]),
        env={
            'POLICIES_PATH': config.policies_path,
            'STATE_PATH': config.state_path,
            'LOGS_PATH': config.logs_path,
            'CREDENTIALS_PATH': config.credentials_path,
            'AGENTGATE_MASTER_PASSWORD': 'pw',
            'ESCALATION_TIMEOUT_SECONDS': '1',
        },
    )
    async with asyncio.timeout(15):
        async with Client(transport) as client:
            status = (await client.call_tool('broker.status', {})).data
            assert status['policies'] == 1
            result = (await client.call_tool('credential.request', {
                'agent': 'demo', 'credential': 'demo-key',
            })).data
            assert result['granted'] is False
            assert result['reason'] == 'escalation timed out'
    assert 'dummy-value' not in Path(config.logs_path).read_text()


@pytest.mark.asyncio
async def test_stale_email_approval_cannot_approve_next_email(tmp_path):
    broker = build_broker(_cfg(tmp_path), 'pw')
    master, slave = pty.openpty()
    terminal = Terminal(slave)
    console = asyncio.create_task(console_loop(broker, terminal))
    first = asyncio.create_task(broker.approvals.submit('agent', 'gmail:send', details='Email A'))
    second = None
    try:
        await asyncio.sleep(0.1)
        request_a = broker.approvals.get_pending()
        assert request_a is not None
        first.cancel()
        await asyncio.gather(first, return_exceptions=True)
        second = asyncio.create_task(broker.approvals.submit('agent', 'gmail:send', details='Email B'))
        await asyncio.sleep(0.1)
        request_b = broker.approvals.get_pending()
        assert request_b is not None
        os.write(master, f'y {request_a.approval_code}\n'.encode())
        await asyncio.sleep(0.1)
        assert not second.done()
        os.write(master, b'y\n')
        await asyncio.sleep(0.1)
        assert not second.done()
        os.write(master, f'y {request_b.approval_code}\n'.encode())
        assert await asyncio.wait_for(second, 2) is True
    finally:
        console.cancel()
        first.cancel()
        if second:
            second.cancel()
        await asyncio.gather(console, first, *([second] if second else []), return_exceptions=True)
        terminal.close()
        os.close(master)
