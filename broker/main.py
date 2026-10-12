from __future__ import annotations

import asyncio
import argparse
import getpass
import os
import sys
import secrets
import webbrowser
import uvicorn

from broker.approval import ApprovalQueue
from broker.audit import AuditLogger
from broker.config import Config, ConfigError
from broker.console import console_loop, open_terminal
from broker.credential_store import CredentialStore
from broker.mcp_server import Broker, build_mcp
from broker.http_auth import RegistryTokenVerifier, read_token_file
from broker.agent_registry import AgentRegistry


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
    operator_token_file: str | None = None, open_app: bool = True,
    bootstrap_agent: str = 'agentgate-local', stdio_agent: str = 'agentgate-local',
) -> None:
    config = config or Config.from_env()
    if http and not token_file:
        raise ConfigError('HTTP mode requires --token-file for bearer authentication.')
    if not 1 <= port <= 65535:
        raise ConfigError('HTTP port must be between 1 and 65535.')
    if operator_token_file and not http:
        raise ConfigError('The app requires HTTP mode.')
    operator_token = read_token_file(operator_token_file) if operator_token_file else None
    if operator_token and token_file and secrets.compare_digest(operator_token, read_token_file(token_file)):
        raise ConfigError('Operator and agent token files must contain different credentials.')
    registry = None
    auth = None
    if http:
        agents_path = config.agents_path or os.path.join(os.path.dirname(config.credentials_path), 'agents.sqlite3')
        registry = AgentRegistry(agents_path)
        registry.import_token(bootstrap_agent, read_token_file(token_file))
        auth = RegistryTokenVerifier(registry)
    terminal = open_terminal()
    tasks = []
    http_server = None
    server_task = None
    launch_task = None
    try:
        if terminal is None:
            if not config.master_password:
                raise ConfigError("headless MCP requires AGENTGATE_MASTER_PASSWORD")
            if not config.escalation_timeout_seconds:
                raise ConfigError("headless MCP requires ESCALATION_TIMEOUT_SECONDS > 0")
        master_password = resolve_master_password(config)
        broker = build_broker(config, master_password)
        broker.agent_registry = registry
        gmail_tools = None
        if operator_token:
            from broker.gmail_tools import GmailTools
            from broker.integrations.gmail import Gmail
            gmail_tools = GmailTools(broker, Gmail(broker.store))
        mcp = build_mcp(broker, auth=auth, gmail_tools=gmail_tools, trusted_agent=stdio_agent) if gmail_tools else build_mcp(broker, auth=auth, trusted_agent=stdio_agent)
        print(format_status_line(broker), file=sys.stderr)
        if http:
            print(f'[AgentGate] authenticated MCP endpoint: http://127.0.0.1:{port}/mcp', file=sys.stderr)
            app = mcp.http_app(
                path='/mcp', transport='http', host_origin_protection=True,
                allowed_hosts=['127.0.0.1', 'localhost'], allowed_origins=[],
            )
            if operator_token:
                from broker.dashboard import create_dashboard
                app = create_dashboard(app, broker, gmail_tools, operator_token)
            http_server = uvicorn.Server(uvicorn.Config(
                app, host='127.0.0.1', port=port, lifespan='on',
                timeout_graceful_shutdown=2,
            ))
            server_task = asyncio.create_task(http_server.serve())
            tasks.append(server_task)
            if operator_token and open_app:
                async def launch_app():
                    while not http_server.started and not server_task.done():
                        await asyncio.sleep(0.05)
                    if http_server.started:
                        # Fragments are never transmitted in HTTP requests/logs.
                        await asyncio.to_thread(webbrowser.open, f'http://127.0.0.1:{port}/app#key={operator_token}')
                launch_task = asyncio.create_task(launch_app())
        else:
            tasks.append(asyncio.create_task(mcp.run_async()))
        if terminal is not None and not operator_token:
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
        if launch_task is not None:
            tasks.append(launch_task)
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
    parser.add_argument('--bootstrap-agent', default='agentgate-local', help='identity assigned to --token-file on first launch')
    parser.add_argument('--stdio-agent', default='agentgate-local', help='trusted identity for STDIO clients')
    parser.add_argument('--app', action='store_true', help='enable the local operator app and open its window')
    parser.add_argument('--operator-token-file', help='separate private app credential, required with --app')
    parser.add_argument('--no-open', action='store_true', help='do not automatically open the app browser')
    args = parser.parse_args()
    if args.app and not args.operator_token_file:
        parser.error('--app requires --operator-token-file')
    if args.operator_token_file and not args.app:
        parser.error('--operator-token-file requires --app')
    try:
        asyncio.run(run(http=args.http or args.app, port=args.port, token_file=args.token_file,
                        operator_token_file=args.operator_token_file, open_app=not args.no_open,
                        bootstrap_agent=args.bootstrap_agent, stdio_agent=args.stdio_agent))
    except ConfigError as exc:
        print(f"[AgentGate] configuration error: {exc}", file=sys.stderr)
        raise SystemExit(2)
    except KeyboardInterrupt:
        print("\n[AgentGate] interrupted", file=sys.stderr)


if __name__ == "__main__":
    main()
