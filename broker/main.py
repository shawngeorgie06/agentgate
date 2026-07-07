from __future__ import annotations

import asyncio
import getpass
import os
import sys
import textwrap

from broker import db_broker, state
from broker.agent_store import AgentStore
from broker.approval import ApprovalQueue
from broker.audit import AuditLogger
from broker.config import Config, ConfigError
from broker.connection_store import ConnectionStore
from broker.credential_store import CredentialStore
from broker.db_executor import AsyncpgExecutor
from broker.db_resource_store import DbResourceStore
from broker.mcp_server import Broker, build_mcp
from broker.ssh_ca_store import SshCaStore
from broker.ssh_resource_store import SshResourceStore


def resolve_master_password(config: Config) -> str:
    if config.master_password:
        return config.master_password
    return getpass.getpass("AgentGate master password: ")


def ensure_policies_file(config: Config) -> bool:
    """First-run bootstrap: create a deny-and-escalate-everything policy file
    so a bare start is safe instead of crashing on a missing file. Returns
    True when the file was created."""
    if os.path.exists(config.policies_path):
        return False
    os.makedirs(os.path.dirname(os.path.abspath(config.policies_path)), exist_ok=True)
    with open(config.policies_path, "w", encoding="utf-8") as fh:
        fh.write(textwrap.dedent("""\
            policies:
              - name: default-deny
                agent: "*"
                credential: "*"
                auto_approve: false
                escalate: true
        """))
    return True


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
        agents=AgentStore(config.agents_path, master_password),
        db_resources=DbResourceStore(config.db_resources_path, master_password),
        db_executor=AsyncpgExecutor(),
        ssh_resources=SshResourceStore(config.ssh_resources_path, master_password),
        ssh_ca=SshCaStore(config.ssh_ca_path, master_password),
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
            broker.audit.log_operator(action="mode-toggle", subject=new_mode)
            print(f"[AgentGate] switched to {new_mode.upper()} mode")
        elif cmd in ("q", "quit", "exit"):
            print("[AgentGate] shutting down")
            return
        else:
            print(format_status_line(broker))


async def _reaper_loop(broker: Broker) -> None:
    """Periodically drop expired agentgate_* roles for every registered
    resource. Stateless — recovers dangling roles after a restart. Never dies
    on a per-resource error."""
    while True:
        await asyncio.sleep(broker.config.db_reap_interval_seconds)
        if broker.db_resources is None or broker.db_executor is None:
            continue
        for name in broker.db_resources.list_names():
            try:
                resource = broker.db_resources.get(name)
                for role in await db_broker.reap(broker.db_executor, resource):
                    broker.audit.log_operator(action="db-reap", subject=role)
            except Exception as exc:
                # Non-sensitive diagnostic only: resource name + exception TYPE.
                # Never str(exc) (an asyncpg error could embed a DSN/password)
                # and never the resource's admin password.
                print(
                    f"[AgentGate] reaper: skipping resource {name!r} "
                    f"({type(exc).__name__})",
                    file=sys.stderr,
                )
                continue


def allowed_hosts(config: Config) -> list[str]:
    """Host headers the MCP endpoint accepts. Anything else is rejected (400)
    to block DNS rebinding: a browser rebound to 127.0.0.1 still sends the
    attacker's hostname in the Host header."""
    hosts = {"127.0.0.1", "localhost", "::1"}
    if config.mcp_host not in ("0.0.0.0", "::"):
        hosts.add(config.mcp_host)
    hosts.update(h.strip() for h in config.mcp_allowed_hosts.split(",") if h.strip())
    return sorted(hosts)


async def run(config: Config | None = None) -> None:
    from starlette.middleware import Middleware
    from starlette.middleware.trustedhost import TrustedHostMiddleware

    config = config or Config.from_env()
    if ensure_policies_file(config):
        print(
            f"[AgentGate] created default policy file (deny + escalate everything) "
            f"at {config.policies_path}"
        )
    master_password = resolve_master_password(config)
    broker = build_broker(config, master_password)
    mcp = build_mcp(broker)

    # MCP is served over HTTP so the terminal (stdin/stdout) belongs entirely
    # to the operator CLI. A stdio MCP transport cannot coexist with an
    # interactive approval prompt in one process: both would read stdin, and
    # every print would corrupt the JSON-RPC stream on stdout.
    print(
        f"[AgentGate] MCP endpoint: http://{config.mcp_host}:{config.mcp_port}/mcp"
    )
    cli_task = asyncio.create_task(_cli_loop(broker))
    reaper_task = asyncio.create_task(_reaper_loop(broker))
    server_task = asyncio.create_task(
        mcp.run_async(
            transport="http",
            host=config.mcp_host,
            port=config.mcp_port,
            show_banner=False,
            middleware=[
                Middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts(config))
            ],
        )
    )
    done, pending = await asyncio.wait(
        {cli_task, reaper_task, server_task}, return_when=asyncio.FIRST_COMPLETED
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
