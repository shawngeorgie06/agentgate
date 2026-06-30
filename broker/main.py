from __future__ import annotations

import asyncio
import getpass
import sys

from broker import state
from broker.approval import ApprovalQueue
from broker.audit import AuditLogger
from broker.config import Config, ConfigError
from broker.connection_store import ConnectionStore
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
        connections=ConnectionStore(config.connections_path, master_password),
    )


def format_status_line(broker: Broker) -> str:
    s = broker.status()
    return (
        f"[AgentGate] running in {s['mode'].upper()} mode | "
        f"policies: {s['policies']} | requests: {s['requests']} | "
        f"escalated: {s['escalated']}"
    )


async def _cli_loop(broker: Broker) -> None:
    loop = asyncio.get_running_loop()
    print(format_status_line(broker))
    while True:
        # Surface any pending approval first.
        pending = broker.approvals.get_pending()
        if pending is not None:
            prompt = (
                f"[AgentGate] pending approval: {pending.agent} "
                f"requesting {pending.credential} [y/n]: "
            )
            answer = await loop.run_in_executor(None, input, prompt)
            broker.approvals.resolve(pending, answer.strip().lower().startswith("y"))
            continue
        answer = await loop.run_in_executor(None, input, "[AgentGate] >> ")
        cmd = answer.strip().lower()
        if cmd == "s":
            new_mode = state.toggle_mode(broker.config.state_path)
            print(f"[AgentGate] switched to {new_mode.upper()} mode")
        elif cmd in ("q", "quit", "exit"):
            print("[AgentGate] shutting down")
            return
        else:
            print(format_status_line(broker))


async def run(config: Config | None = None) -> None:
    config = config or Config.from_env()
    master_password = resolve_master_password(config)
    broker = build_broker(config, master_password)
    mcp = build_mcp(broker)

    cli_task = asyncio.create_task(_cli_loop(broker))
    server_task = asyncio.create_task(mcp.run_async())
    done, pending = await asyncio.wait(
        {cli_task, server_task}, return_when=asyncio.FIRST_COMPLETED
    )
    for task in pending:
        task.cancel()


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
