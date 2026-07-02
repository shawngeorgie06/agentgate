from __future__ import annotations

import asyncio
import socket
import textwrap

from fastmcp import Client

from broker.agent_store import AgentStore
from broker.approval import ApprovalQueue
from broker.audit import AuditLogger
from broker.config import Config
from broker.credential_store import CredentialStore
from broker.mcp_server import Broker, build_mcp
from broker.policy_engine import PolicyEngine


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def test_agent_reaches_broker_over_http_transport(tmp_path):
    """End-to-end over the real deployment shape: the MCP server on HTTP,
    a client connecting via URL — proving agents can actually reach the
    broker while the terminal stays free for the operator CLI."""
    pol = tmp_path / "policies.yaml"
    pol.write_text(textwrap.dedent("""
        policies:
          - name: cc-anthropic
            agent: claude-code
            credential: anthropic-api-key
            auto_approve: true
          - name: default-deny
            agent: "*"
            credential: "*"
            auto_approve: false
            escalate: true
    """))
    cfg = Config.from_env({
        "POLICIES_PATH": str(pol),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTS_PATH": str(tmp_path / "agents.json"),
    })
    store = CredentialStore(cfg.credentials_path, "pw")
    store.store("anthropic-api-key", "sk-secret")
    agents = AgentStore(cfg.agents_path, "pw")
    key = agents.register("claude-code")
    broker = Broker(
        config=cfg, store=store,
        engine=PolicyEngine.from_file(cfg.policies_path),
        audit=AuditLogger(cfg.logs_path), approvals=ApprovalQueue(),
        agents=agents,
    )
    port = _free_port()
    from broker.main import allowed_hosts
    from starlette.middleware import Middleware
    from starlette.middleware.trustedhost import TrustedHostMiddleware
    server = asyncio.create_task(build_mcp(broker).run_async(
        transport="http", host="127.0.0.1", port=port, show_banner=False,
        middleware=[Middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts(cfg))],
    ))
    try:
        url = f"http://127.0.0.1:{port}/mcp"
        last_exc: Exception | None = None
        for _ in range(50):
            try:
                async with Client(url) as client:
                    res = await client.call_tool("credential_request", {
                        "agent": "claude-code", "agent_key": key,
                        "credential": "anthropic-api-key",
                    })
                break
            except Exception as exc:  # server not up yet
                last_exc = exc
                await asyncio.sleep(0.1)
        else:
            raise AssertionError(f"MCP server never became reachable: {last_exc}")
        assert res.data["granted"] is True
        assert res.data["value"] == "sk-secret"

        # DNS-rebinding defense: a rebound browser reaches 127.0.0.1 but still
        # sends the attacker's hostname in Host — the server must reject it.
        import httpx
        async with httpx.AsyncClient() as http:
            resp = await http.post(url, json={}, headers={"Host": "evil.example"})
        assert resp.status_code == 400
    finally:
        server.cancel()
        try:
            await server
        except (asyncio.CancelledError, Exception):
            pass
