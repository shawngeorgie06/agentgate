"""Operator input uses the controlling terminal, never MCP stdin/stdout."""
from __future__ import annotations

import asyncio
import select
import os
import json

from broker import state
from broker.mcp_server import Broker


class Terminal:
    def __init__(self, fd: int) -> None:
        self.reader = os.fdopen(fd, 'rb', buffering=0)
        self.writer = os.fdopen(os.dup(fd), 'w', encoding='utf-8', buffering=1)

    def fileno(self):
        return self.reader.fileno()

    def readline(self):
        return self.reader.readline().decode('utf-8', errors='replace')

    def write(self, text):
        self.writer.write(text)
        self.writer.flush()

    def flush(self):
        self.writer.flush()

    def close(self):
        self.reader.close()
        self.writer.close()


def open_terminal() -> Terminal | None:
    try:
        return Terminal(os.open('/dev/tty', os.O_RDWR))
    except OSError:
        return None


async def console_loop(broker: Broker, terminal: Terminal) -> None:
    terminal.write('[AgentGate] s: toggle approval mode | q: quit\n')
    prompted = None
    while True:
        pending = broker.approvals.get_pending()
        if pending is not prompted:
            prompted = pending
            if pending is not None:
                if pending.details:
                    terminal.write(f'\n{pending.details}\n')
                choices = f'[approve: y {pending.approval_code}; deny: n]' if pending.details else '[y/n]'
                terminal.write(
                    f'[AgentGate] {json.dumps(pending.agent)} requesting '
                    f'{json.dumps(pending.credential)} {choices}: '
                )
                terminal.flush()
        readable, _, _ = select.select([terminal], [], [], 0)
        if readable:
            line = terminal.readline()
            if not line:
                return
            command = line.strip().lower()
            if command in ('q', 'quit', 'exit'):
                return
            if command == 's':
                mode = state.toggle_mode(broker.config.state_path)
                terminal.write(f'[AgentGate] switched to {mode.upper()} mode\n')
            elif pending is not None and command == 'n':
                broker.approvals.resolve(pending, False)
            elif pending is not None and command == (
                f'y {pending.approval_code}' if pending.details else 'y'
            ):
                broker.approvals.resolve(pending, True)
            else:
                terminal.write('[AgentGate] use the displayed approval command, n to deny, s for mode, q to quit\n')
        await asyncio.sleep(0.05)
