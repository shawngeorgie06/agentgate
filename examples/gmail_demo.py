"""Offline Gmail approval walkthrough. No Google connection or real email."""
import asyncio
import base64
import tempfile
from email.message import EmailMessage
from pathlib import Path

from fastmcp import Client, FastMCP

from broker.config import Config
from broker.console import console_loop, open_terminal
from broker.gmail_tools import register_gmail_tools
from broker.integrations.gmail import describe_message
from broker.main import build_broker


class DummyGmail:
    def __init__(self):
        self.raw = ''

    def call(self, operation, **arguments):
        if operation == 'draft':
            message = EmailMessage()
            message['To'] = arguments['to']
            message['Subject'] = arguments['subject']
            message.set_content(arguments['body'])
            self.raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
            return {'id': 'dummy-draft'}
        if operation == 'snapshot':
            return {'raw': self.raw, 'preview': describe_message(self.raw)}
        if operation == 'send':
            return {'id': 'dummy-sent-message', 'simulation': True}
        raise ValueError('Unsupported demo operation')


async def main():
    terminal = open_terminal()
    if terminal is None:
        raise SystemExit('Run this demo from an interactive terminal.')
    try:
        with tempfile.TemporaryDirectory(prefix='agentgate-gmail-demo-') as directory:
            root = Path(directory)
            (root / 'policies.yaml').write_text('''policies:
  - name: demo
    agent: demo-agent
    credential: "*"
    auto_approve: true
''')
            config = Config.from_env({
                'POLICIES_PATH': str(root / 'policies.yaml'),
                'STATE_PATH': str(root / 'mode.json'),
                'LOGS_PATH': str(root / 'audit.log'),
                'CREDENTIALS_PATH': str(root / 'credentials.json'),
                'ESCALATION_TIMEOUT_SECONDS': '60',
            })
            broker = build_broker(config, 'dummy-password')
            mcp = FastMCP('Offline Gmail demo')
            register_gmail_tools(mcp, broker, DummyGmail())
            operator = asyncio.create_task(console_loop(broker, terminal))
            request = None
            try:
                async with Client(mcp) as client:
                    await client.call_tool('gmail.draft', {
                        'agent': 'demo-agent', 'to': 'recipient@example.test',
                        'subject': 'AgentGate approval demo',
                        'body': 'This is a simulated email. No real email will be sent.',
                    })
                    print('Dummy draft created. Review it below; type the displayed y + code to simulate sending, or n to deny.')
                    request = asyncio.create_task(client.call_tool('gmail.send_draft', {
                        'agent': 'demo-agent', 'draft_id': 'dummy-draft',
                    }))
                    done, _ = await asyncio.wait({request, operator}, return_when=asyncio.FIRST_COMPLETED)
                    if request in done:
                        result = request.result().data
                        print(f"Simulation result: {result}")
            finally:
                if request is not None:
                    request.cancel()
                operator.cancel()
                await asyncio.gather(operator, *([request] if request else []), return_exceptions=True)
    finally:
        terminal.close()


if __name__ == '__main__':
    asyncio.run(main())
