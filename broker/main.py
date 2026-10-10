from __future__ import annotations

import asyncio
import argparse
import getpass
import sys
import uvicorn

from broker.approval import ApprovalQueue
from broker.audit import AuditLogger
from broker.config import Config, ConfigError
from broker.console import console_loop, open_terminal
from broker.credential_store import CredentialStore
from broker.mcp_server import Broker, build_mcp
from broker.http_auth import token_verifier


def resolve_master_password(config: Config) -> str:
    if config.master_password:
        return config.master_password
    return getpass.getpass("AgentGate master password: ")


def build_broker(config: Config, master_password: str) -> Broker:
    store = CredentialStore(config.credentials_path, master_password)
    from broker.policy_engine import PolicyEngine
    return Broker(
        config=config,
        store=store,
        engine=PolicyEngine.from_file(config.policies_path),
        audit=AuditLogger(config.logs_path),
        approvals=ApprovalQueue(),
    )


def format_status_line(broker: Broker) -> str:
    s = broker.status()
    return (
        f"[AgentGate] running in {s['mode'].upper()} mode | "
        f"policies: {s['policies']} | requests: {s['requests']} | "
        f"escalated: {s['escalated']}"
    )


async def run(
    config: Config | None = None, *, http: bool = False,
    port: int = 8765, token_file: str | None = None,
) -> None:
    config = config or Config.from_env()
    if http and not token_file:
        raise ConfigError('HTTP mode requires --token-file for bearer authentication.')
    if not 1 <= port <= 65535:
        raise ConfigError('HTTP port must be between 1 and 65535.')
    auth = token_verifier(token_file) if http else None
    terminal = open_terminal()
    tasks = []
    http_server = None
    server_task = None
    try:
        if terminal is None:
            if not config.master_password:
                raise ConfigError("headless MCP requires AGENTGATE_MASTER_PASSWORD")
            if not config.escalation_timeout_seconds:
                raise ConfigError("headless MCP requires ESCALATION_TIMEOUT_SECONDS > 0")
        master_password = resolve_master_password(config)
        broker = build_broker(config, master_password)
        mcp = build_mcp(broker, auth=auth)
        print(format_status_line(broker), file=sys.stderr)
        if http:
            print(f'[AgentGate] authenticated MCP endpoint: http://127.0.0.1:{port}/mcp', file=sys.stderr)
            app = mcp.http_app(
                path='/mcp', transport='http', host_origin_protection=True,
                allowed_hosts=['127.0.0.1', 'localhost'], allowed_origins=[],
            )
            http_server = uvicorn.Server(uvicorn.Config(
                app, host='127.0.0.1', port=port, lifespan='on',
                timeout_graceful_shutdown=2,
            ))
            server_task = asyncio.create_task(http_server.serve())
            tasks.append(server_task)
        else:
            tasks.append(asyncio.create_task(mcp.run_async()))
        if terminal is not None:
            tasks.append(asyncio.create_task(console_loop(broker, terminal)))
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        # Let Uvicorn close its ASGI lifespan before cancelling tasks. Direct
        # cancellation can leave the HTTP session manager hanging on shutdown.
        if http_server is not None and server_task is not None:
            http_server.should_exit = True
            try:
                await asyncio.wait_for(asyncio.shield(server_task), timeout=5)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                server_task.cancel()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if terminal is not None:
            terminal.close()


def main() -> None:
    parser = argparse.ArgumentParser(description='AgentGate MCP broker')
    parser.add_argument('--http', action='store_true', help='serve authenticated MCP on localhost')
    parser.add_argument('--port', type=int, default=8765, help='localhost HTTP port (default: 8765)')
    parser.add_argument('--token-file', help='private bearer token file required for HTTP')
    args = parser.parse_args()
    try:
        asyncio.run(run(http=args.http, port=args.port, token_file=args.token_file))
    except ConfigError as exc:
        print(f"[AgentGate] configuration error: {exc}", file=sys.stderr)
        raise SystemExit(2)
    except KeyboardInterrupt:
        print("\n[AgentGate] interrupted", file=sys.stderr)


if __name__ == "__main__":
    main()
