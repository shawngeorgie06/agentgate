import asyncio
import json
import os
import pty
import re
import select
import socket
import subprocess
import sys
from pathlib import Path

import pytest
import requests
from fastmcp import Client

from broker.config import ConfigError
from broker.http_auth import create_token_file, read_token_file
from broker.main import run


def test_token_file_is_private_and_not_overwritten(tmp_path):
    path = tmp_path / 'private' / 'token'
    create_token_file(str(path))
    token = read_token_file(str(path))
    assert len(token) >= 32
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        create_token_file(str(path))
    assert read_token_file(str(path)) == token


@pytest.mark.parametrize('mode,value', [(0o644, 'x' * 43), (0o600, 'short'), (0o600, 'x' * 514)])
def test_invalid_token_file_rejected(tmp_path, mode, value):
    path = tmp_path / 'token'
    path.write_text(value)
    path.chmod(mode)
    with pytest.raises(ConfigError):
        read_token_file(str(path))


def test_symlink_token_file_rejected(tmp_path):
    path = tmp_path / 'token'
    create_token_file(str(path))
    link = tmp_path / 'link'
    link.symlink_to(path)
    with pytest.raises(ConfigError):
        read_token_file(str(link))


@pytest.mark.asyncio
async def test_http_never_starts_without_authentication():
    with pytest.raises(ConfigError, match='--token-file'):
        await run(http=True)


_SERVER = '''
import os, fcntl, termios, signal
# Closing the synthetic PTY must not kill the child during final cleanup.
signal.signal(signal.SIGHUP, signal.SIG_IGN)
os.setsid()
fcntl.ioctl(int(os.environ['TEST_TTY_FD']), termios.TIOCSCTTY, 0)
from tests.test_gmail import FakeService
from broker.integrations.gmail import Gmail
from broker.gmail_tools import register_gmail_tools
from broker import mcp_server
fake = FakeService()
mcp_server.register_gmail_tools = lambda mcp, broker, **kwargs: register_gmail_tools(
    mcp, broker, Gmail(broker.store, service_factory=lambda: fake), **kwargs
)
from broker.main import main
main()
'''


async def terminal_until(master, needle):
    text = b''
    async with asyncio.timeout(5):
        while needle not in text:
            if select.select([master], [], [], 0)[0]:
                text += os.read(master, 4096)
            else:
                await asyncio.sleep(0.02)
    return text.decode()


@pytest.mark.asyncio
@pytest.mark.parametrize('approve', [True, False])
async def test_real_http_auth_and_terminal_send_approval(tmp_path, approve):
    token_path = tmp_path / 'token'
    create_token_file(str(token_path))
    token = read_token_file(str(token_path))
    policies = tmp_path / 'policies.yaml'
    policies.write_text('''policies:
  - name: local
    agent: local-agent
    credential: "*"
    auto_approve: true
''')
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    master, slave = pty.openpty()
    error_log = open(tmp_path / 'server.log', 'w')
    process = subprocess.Popen(
        [sys.executable, '-c', _SERVER, '--http', '--port', str(port), '--token-file', str(token_path), '--bootstrap-agent', 'local-agent'],
        cwd=str(Path(__file__).resolve().parents[1]),
        env={**os.environ, 'TEST_TTY_FD': str(slave),
             'POLICIES_PATH': str(policies), 'STATE_PATH': str(tmp_path / 'mode.json'),
             'LOGS_PATH': str(tmp_path / 'audit.log'), 'CREDENTIALS_PATH': str(tmp_path / 'credentials.json'),
             'AGENTGATE_MASTER_PASSWORD': 'dummy-password', 'ESCALATION_TIMEOUT_SECONDS': '5'},
        pass_fds=(slave,), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=error_log,
    )
    os.close(slave)
    url = f'http://127.0.0.1:{port}/mcp'
    try:
        async with asyncio.timeout(10):
            while True:
                assert process.poll() is None, (tmp_path / 'server.log').read_text().replace(token, '[redacted]')
                try:
                    response = await asyncio.to_thread(requests.get, url, timeout=1)
                    break
                except requests.ConnectionError:
                    await asyncio.sleep(0.05)
        assert response.status_code == 401
        wrong = await asyncio.to_thread(requests.get, url, headers={'Authorization': 'Bearer wrong'}, timeout=1)
        assert wrong.status_code == 401
        for headers in ({'Host': 'foreign.example'}, {'Origin': 'https://foreign.example'}):
            rejected = await asyncio.to_thread(requests.get, url, headers={
                'Authorization': f'Bearer {token}', **headers,
            }, timeout=1)
            assert rejected.status_code in (403, 421)
        async with Client(url, auth=token) as client:
            assert (await client.call_tool('broker.status', {})).data['policies'] == 1
            agent_process = await asyncio.create_subprocess_exec(
                sys.executable, '-m', 'cli.agent', '--port', str(port),
                '--token-file', str(token_path), '--agent', 'local-agent',
                'send-draft', 'draft-1', stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            request = asyncio.create_task(agent_process.communicate())
            preview = await terminal_until(master, b'; deny: n]')
            assert 'recipient@example.test' in preview
            assert 'Test subject' in preview
            code = re.search(r'approve: y ([a-f0-9]{6})', preview).group(1)
            os.write(master, b'y wrong-code\n')
            await asyncio.sleep(0.15)
            assert not request.done()
            os.write(master, f'y {code}\n'.encode() if approve else b'n\n')
            stdout, stderr = await asyncio.wait_for(request, 5)
            result = json.loads(stdout)
            assert not stderr
            assert token not in stdout.decode()
            assert agent_process.returncode == (0 if approve else 1)
            assert result['ok'] is approve
            if approve:
                assert result['data']['id'] == 'sent-1'
        os.write(master, b'q\n')
        async with asyncio.timeout(5):
            while 'Finished server process' not in (tmp_path / 'server.log').read_text():
                await asyncio.sleep(0.02)
        # macOS can retain an exiting PTY session leader until its master closes.
        os.close(master)
        master = None
        await asyncio.to_thread(process.wait, timeout=5)
        assert process.returncode == 0
        rows = [json.loads(line) for line in (tmp_path / 'audit.log').read_text().splitlines()]
        expected = ['escalated', 'approved', 'completed'] if approve else ['escalated', 'denied']
        assert [row['decision'] for row in rows if row['credential_requested'] == 'gmail:send'] == expected
        assert token not in (tmp_path / 'audit.log').read_text()
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        if master is not None:
            os.close(master)
        error_log.close()


def test_fifo_token_file_rejected_without_blocking(tmp_path):
    path = tmp_path / 'fifo'
    os.mkfifo(path, 0o600)
    with pytest.raises(ConfigError):
        read_token_file(str(path))
