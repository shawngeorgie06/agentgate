from __future__ import annotations

import asyncio
import getpass
import sys

from broker.approval import ApprovalQueue
from broker.audit import AuditLogger
from broker.config import Config, ConfigError
from broker.console import console_loop, open_terminal
from broker.credential_store import CredentialStore
from broker.mcp_server import Broker, build_mcp


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


async def run(config: Config | None = None) -> None:
    config = config or Config.from_env()
    terminal = open_terminal()
    tasks = []
    try:
        if terminal is None:
            if not config.master_password:
                raise ConfigError("headless MCP requires AGENTGATE_MASTER_PASSWORD")
            if not config.escalation_timeout_seconds:
                raise ConfigError("headless MCP requires ESCALATION_TIMEOUT_SECONDS > 0")
        master_password = resolve_master_password(config)
        broker = build_broker(config, master_password)
        mcp = build_mcp(broker)
        print(format_status_line(broker), file=sys.stderr)
        tasks.append(asyncio.create_task(mcp.run_async()))
        if terminal is not None:
            tasks.append(asyncio.create_task(console_loop(broker, terminal)))
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if terminal is not None:
            terminal.close()


def main() -> None:
    try:
        asyncio.run(run())
    except ConfigError as exc:
        print(f"[AgentGate] configuration error: {exc}", file=sys.stderr)
        raise SystemExit(2)
    except KeyboardInterrupt:
        print("\n[AgentGate] interrupted", file=sys.stderr)


if __name__ == "__main__":
    main()
