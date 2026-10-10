"""Run with .venv/bin/python -m examples.demo; uses temporary dummy data only."""
import asyncio
import json
import tempfile
from pathlib import Path

from fastmcp import Client

from broker.config import Config
from broker.console import console_loop, open_terminal
from broker.main import build_broker
from broker.mcp_server import build_mcp


async def main():
    terminal = open_terminal()
    if terminal is None:
        raise SystemExit('Run this demo from an interactive terminal.')
    with tempfile.TemporaryDirectory(prefix='agentgate-demo-') as directory:
        root = Path(directory)
        policies = root / 'policies.yaml'
        policies.write_text('policies: []\n')
        config = Config.from_env({
            'POLICIES_PATH': str(policies),
            'STATE_PATH': str(root / 'mode.json'),
            'LOGS_PATH': str(root / 'audit.log'),
            'CREDENTIALS_PATH': str(root / 'credentials.json'),
            'ESCALATION_TIMEOUT_SECONDS': '60',
        })
        broker = build_broker(config, 'demo-password-only')
        broker.store.store('demo-key', 'dummy-value-only')
        operator = asyncio.create_task(console_loop(broker, terminal))
        try:
            async with Client(build_mcp(broker)) as client:
                for instruction in ('Approve with y', 'Deny with n'):
                    print(f'\n{instruction}: requesting demo-key through MCP.')
                    request = asyncio.create_task(client.call_tool(
                        'credential.request', {'agent': 'demo-agent', 'credential': 'demo-key'}
                    ))
                    done, _ = await asyncio.wait(
                        {request, operator}, return_when=asyncio.FIRST_COMPLETED
                    )
                    if request not in done:
                        request.cancel()
                        await asyncio.gather(request, return_exceptions=True)
                        return
                    result = request.result().data
                    print(f"Granted: {result['granted']}; reason: {result['reason']}")
            decisions = [json.loads(line)['decision'] for line in (root / 'audit.log').read_text().splitlines()]
            print(f'Audit decisions: {decisions}')
        finally:
            operator.cancel()
            await asyncio.gather(operator, return_exceptions=True)
            terminal.close()


if __name__ == '__main__':
    asyncio.run(main())
