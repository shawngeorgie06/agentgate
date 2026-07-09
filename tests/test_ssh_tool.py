# tests/test_ssh_tool.py
from __future__ import annotations

import json
import textwrap

import pytest

from broker.agent_store import AgentStore
from broker.approval import ApprovalQueue
from broker.audit import AuditLogger
from broker.config import Config
from broker.credential_store import CredentialStore
from broker.mcp_server import Broker, build_mcp
from broker.policy_engine import PolicyEngine
from broker.ssh_ca_store import SshCaStore
from broker.ssh_resource_store import SshResource, SshResourceStore
from broker.ssh_revocation_store import SshRevocationStore

_NULL_FIELDS = ("host", "port", "username", "private_key", "certificate", "expires_at")


def _write_policies(tmp_path, body):
    p = tmp_path / "policies.yaml"
    p.write_text(textwrap.dedent(body))
    return str(p)


def _make_broker(tmp_path, *, policies, with_ssh=True, ca_initialized=True, revoke=None):
    cfg = Config.from_env({
        "POLICIES_PATH": _write_policies(tmp_path, policies),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTS_PATH": str(tmp_path / "agents.json"),
        "SSH_CA_PATH": str(tmp_path / "ssh_ca.json"),
        "SSH_RESOURCES_PATH": str(tmp_path / "ssh.json"),
        "SSH_REVOCATIONS_PATH": str(tmp_path / "revocations.json"),
    })
    agents = AgentStore(cfg.agents_path, "pw")
    agent_key = agents.register("claude-code")
    ssh_resources = None
    ssh_ca = None
    if with_ssh:
        ssh_resources = SshResourceStore(cfg.ssh_resources_path, "pw")
        ssh_resources.store(SshResource(
            name="web-1", host="10.0.0.5", port=22, principal="deploy",
            force_command=None, created_at="2026-07-05T10:00:00+00:00",
        ))
        ssh_ca = SshCaStore(cfg.ssh_ca_path, "pw")
        if ca_initialized:
            ssh_ca.initialize()
    revocations = SshRevocationStore(cfg.ssh_revocations_path, "pw")
    if revoke:
        agent_name, resource_name = revoke
        from broker.ssh_validation import ssh_key_id
        revocations.revoke(
            key_id=ssh_key_id(agent_name, resource_name),
            agent=agent_name, resource=resource_name,
            revoked_at="2026-07-08T00:00:00+00:00",
        )
    broker = Broker(
        config=cfg,
        store=CredentialStore(cfg.credentials_path, "pw"),
        engine=PolicyEngine.from_file(cfg.policies_path),
        audit=AuditLogger(cfg.logs_path),
        approvals=ApprovalQueue(),
        agents=agents,
        ssh_resources=ssh_resources,
        ssh_ca=ssh_ca,
        ssh_revocations=revocations,
    )
    return broker, agent_key, tmp_path / "audit.log"


_ALLOW = """
    policies:
      - name: cc-ssh
        agent: claude-code
        credential: web-1
        auto_approve: true
        escalate: false
"""

_DENY = """
    policies:
      - name: no-ssh
        agent: "*"
        credential: "*"
        auto_approve: false
        escalate: false
"""


def _assert_denied_shape(result):
    assert result["granted"] is False
    for f in _NULL_FIELDS:
        assert result[f] is None, f


async def test_grant_returns_key_cert_and_audits_without_private_key(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW)
    result = await broker.request_ssh_certificate("claude-code", key, "web-1")
    assert result["granted"] is True
    assert result["host"] == "10.0.0.5" and result["port"] == 22
    assert result["username"] == "deploy"
    assert result["private_key"].startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert result["certificate"].startswith("ssh-ed25519-cert-v01@openssh.com ")
    assert result["expires_at"]
    log_text = log.read_text()
    entry = json.loads(log_text.strip().splitlines()[-1])
    assert entry["decision"] == "approved"
    assert entry["username"] == "deploy"
    assert entry["key_id"] == "agentgate:claude-code:web-1"
    # The private key must NEVER appear anywhere in the audit file.
    assert "PRIVATE KEY" not in log_text
    body = result["private_key"].strip().splitlines()[1]  # a base64 line of the key
    assert body not in log_text


async def test_revoked_key_id_denied_and_never_signs(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW, revoke=("claude-code", "web-1"))
    result = await broker.request_ssh_certificate("claude-code", key, "web-1")
    _assert_denied_shape(result)
    assert result["reason"] == "credential revoked"
    entry = json.loads(log.read_text().strip().splitlines()[-1])
    assert entry["decision"] == "denied"


async def test_non_revoked_pairing_still_grants(tmp_path):
    # Revoking a DIFFERENT resource must not block web-1.
    broker, key, _log = _make_broker(tmp_path, policies=_ALLOW, revoke=("claude-code", "other"))
    result = await broker.request_ssh_certificate("claude-code", key, "web-1")
    assert result["granted"] is True


async def test_revocation_store_failure_fails_closed(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW)

    class _Boom:
        def is_revoked(self, key_id):
            raise RuntimeError("REVOCATION_STORE_DETAIL")

    broker.ssh_revocations = _Boom()
    result = await broker.request_ssh_certificate("claude-code", key, "web-1")
    _assert_denied_shape(result)
    assert "REVOCATION_STORE_DETAIL" not in result["reason"]
    log_text = log.read_text()
    assert '"decision": "denied"' in log_text
    assert "REVOCATION_STORE_DETAIL" not in log_text


async def test_unknown_agent_denied_and_never_escalates(tmp_path):
    broker, _key, log = _make_broker(tmp_path, policies=_ALLOW)
    result = await broker.request_ssh_certificate("ghost", "bad-key", "web-1")
    _assert_denied_shape(result)
    assert broker.approvals.pending_count() == 0
    assert '"decision": "denied"' in log.read_text()


async def test_policy_hard_deny(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_DENY)
    result = await broker.request_ssh_certificate("claude-code", key, "web-1")
    _assert_denied_shape(result)
    assert "denied by policy" in result["reason"]
    assert '"decision": "denied"' in log.read_text()


async def test_unknown_resource_fails_closed(tmp_path):
    broker, key, log = _make_broker(
        tmp_path,
        policies="""
    policies:
      - name: cc-ssh
        agent: claude-code
        credential: "*"
        auto_approve: true
        escalate: false
""",
    )
    result = await broker.request_ssh_certificate("claude-code", key, "nope")
    _assert_denied_shape(result)
    assert "unknown ssh resource" in result["reason"]
    assert '"decision": "denied"' in log.read_text()


async def test_no_ssh_stores_configured_fails_closed(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW, with_ssh=False)
    result = await broker.request_ssh_certificate("claude-code", key, "web-1")
    _assert_denied_shape(result)
    assert '"decision": "denied"' in log.read_text()


async def test_uninitialized_ca_fails_closed(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW, ca_initialized=False)
    result = await broker.request_ssh_certificate("claude-code", key, "web-1")
    _assert_denied_shape(result)
    assert "ssh CA not initialized" in result["reason"]
    assert '"decision": "denied"' in log.read_text()


async def test_resource_store_failure_fails_closed_generic(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW)

    class _Boom:
        def get(self, name):
            raise RuntimeError("SENSITIVE_STORE_DETAIL")

    broker.ssh_resources = _Boom()
    result = await broker.request_ssh_certificate("claude-code", key, "web-1")
    _assert_denied_shape(result)
    assert "SENSITIVE_STORE_DETAIL" not in result["reason"]
    log_text = log.read_text()
    assert '"decision": "denied"' in log_text
    assert "SENSITIVE_STORE_DETAIL" not in log_text


async def test_ca_store_failure_fails_closed_generic(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW)

    class _Boom:
        def load_private_pem(self):
            raise RuntimeError("SENSITIVE_CA_DETAIL")

    broker.ssh_ca = _Boom()
    result = await broker.request_ssh_certificate("claude-code", key, "web-1")
    _assert_denied_shape(result)
    assert "SENSITIVE_CA_DETAIL" not in result["reason"]
    assert "could not access ssh CA" in result["reason"]
    log_text = log.read_text()
    assert '"decision": "denied"' in log_text
    assert "SENSITIVE_CA_DETAIL" not in log_text


async def test_signing_failure_fails_closed_generic(tmp_path, monkeypatch):
    from broker import mcp_server as m
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW)

    def boom(*a, **kw):
        raise RuntimeError("SENSITIVE_SIGNING_DETAIL")

    monkeypatch.setattr(m.ssh_ca, "issue_certificate", boom)
    result = await broker.request_ssh_certificate("claude-code", key, "web-1")
    _assert_denied_shape(result)
    assert "SENSITIVE_SIGNING_DETAIL" not in result["reason"]
    assert "could not issue certificate" in result["reason"]
    log_text = log.read_text()
    assert '"decision": "denied"' in log_text
    assert "SENSITIVE_SIGNING_DETAIL" not in log_text


async def test_tool_registered_with_underscore_name(tmp_path):
    from fastmcp import Client
    broker, key, _log = _make_broker(tmp_path, policies=_ALLOW)
    mcp = build_mcp(broker)
    async with Client(mcp) as client:
        names = [t.name for t in await client.list_tools()]
        assert "ssh_certificate_request" in names
        res = await client.call_tool("ssh_certificate_request", {
            "agent": "claude-code", "agent_key": key, "resource": "web-1"})
        assert res.data["granted"] is True
