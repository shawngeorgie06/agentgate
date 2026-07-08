# tests/test_aws_tool.py
from __future__ import annotations

import json
import textwrap

from broker.agent_store import AgentStore
from broker.approval import ApprovalQueue
from broker.audit import AuditLogger
from broker.aws_key_store import AwsKeyStore
from broker.aws_resource_store import AwsResource, AwsResourceStore
from broker.config import Config
from broker.credential_store import CredentialStore
from broker.mcp_server import Broker, build_mcp
from broker.policy_engine import PolicyEngine

_NULL_FIELDS = ("access_key_id", "secret_access_key", "session_token", "expiration", "region")


class _FakeSts:
    def __init__(self, exc=None):
        self._exc = exc

    async def assume_role(self, access_key_id, secret_access_key, *, role_arn,
                          session_name, duration_seconds, region, external_id):
        if self._exc is not None:
            raise self._exc
        return {"access_key_id": "ASIA_TEMP", "secret_access_key": "TEMP_SECRET_XYZ",
                "session_token": "TEMP_TOKEN_XYZ",
                "expiration": "2026-07-06T10:15:00+00:00"}


def _make_broker(tmp_path, *, policies, with_aws=True, key_set=True, sts=None):
    p = tmp_path / "policies.yaml"
    p.write_text(textwrap.dedent(policies))
    cfg = Config.from_env({
        "POLICIES_PATH": str(p),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTS_PATH": str(tmp_path / "agents.json"),
        "AWS_KEY_PATH": str(tmp_path / "aws_key.json"),
        "AWS_RESOURCES_PATH": str(tmp_path / "aws.json"),
    })
    agents = AgentStore(cfg.agents_path, "pw")
    agent_key = agents.register("claude-code")
    aws_resources = aws_key = None
    if with_aws:
        aws_resources = AwsResourceStore(cfg.aws_resources_path, "pw")
        aws_resources.store(AwsResource(
            name="s3-reader", role_arn="arn:aws:iam::123456789012:role/agent-s3-reader",
            region="us-east-1", external_id=None, created_at="2026-07-06T10:00:00+00:00"))
        aws_key = AwsKeyStore(cfg.aws_key_path, "pw")
        if key_set:
            aws_key.set("AKIA_BROKER", "broker-secret")
    broker = Broker(
        config=cfg,
        store=CredentialStore(cfg.credentials_path, "pw"),
        engine=PolicyEngine.from_file(cfg.policies_path),
        audit=AuditLogger(cfg.logs_path),
        approvals=ApprovalQueue(),
        agents=agents,
        aws_resources=aws_resources,
        aws_key=aws_key,
        aws_executor=sts if sts is not None else _FakeSts(),
    )
    return broker, agent_key, tmp_path / "audit.log"


_ALLOW = """
    policies:
      - name: cc-aws
        agent: claude-code
        credential: s3-reader
        auto_approve: true
        escalate: false
"""

_DENY = """
    policies:
      - name: no-aws
        agent: "*"
        credential: "*"
        auto_approve: false
        escalate: false
"""


def _assert_denied_shape(result):
    assert result["granted"] is False
    for f in _NULL_FIELDS:
        assert result[f] is None, f


async def test_grant_returns_temp_creds_and_audits_without_secrets(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW)
    result = await broker.request_aws_credentials("claude-code", key, "s3-reader")
    assert result["granted"] is True
    assert result["access_key_id"] == "ASIA_TEMP"
    assert result["secret_access_key"] == "TEMP_SECRET_XYZ"
    assert result["session_token"] == "TEMP_TOKEN_XYZ"
    assert result["expiration"] == "2026-07-06T10:15:00+00:00"
    assert result["region"] == "us-east-1"
    log_text = log.read_text()
    entry = json.loads(log_text.strip().splitlines()[-1])
    assert entry["decision"] == "approved"
    assert entry["role_arn"] == "arn:aws:iam::123456789012:role/agent-s3-reader"
    # Secrets must NEVER appear in the audit file.
    assert "TEMP_SECRET_XYZ" not in log_text
    assert "TEMP_TOKEN_XYZ" not in log_text


async def test_unknown_agent_denied_and_never_escalates(tmp_path):
    broker, _key, log = _make_broker(tmp_path, policies=_ALLOW)
    result = await broker.request_aws_credentials("ghost", "bad", "s3-reader")
    _assert_denied_shape(result)
    assert broker.approvals.pending_count() == 0
    assert '"decision": "denied"' in log.read_text()


async def test_policy_hard_deny(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_DENY)
    result = await broker.request_aws_credentials("claude-code", key, "s3-reader")
    _assert_denied_shape(result)
    assert "denied by policy" in result["reason"]
    assert '"decision": "denied"' in log.read_text()


async def test_unknown_resource_fails_closed(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies="""
    policies:
      - name: cc-aws
        agent: claude-code
        credential: "*"
        auto_approve: true
        escalate: false
""")
    result = await broker.request_aws_credentials("claude-code", key, "nope")
    _assert_denied_shape(result)
    assert "unknown aws resource" in result["reason"]
    assert '"decision": "denied"' in log.read_text()


async def test_no_aws_stores_configured_fails_closed(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW, with_aws=False)
    result = await broker.request_aws_credentials("claude-code", key, "s3-reader")
    _assert_denied_shape(result)
    assert '"decision": "denied"' in log.read_text()


async def test_key_not_set_fails_closed(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW, key_set=False)
    result = await broker.request_aws_credentials("claude-code", key, "s3-reader")
    _assert_denied_shape(result)
    assert "aws broker key not set" in result["reason"]
    assert '"decision": "denied"' in log.read_text()


async def test_sts_failure_fails_closed_generic(tmp_path):
    broker, key, log = _make_broker(
        tmp_path, policies=_ALLOW, sts=_FakeSts(exc=RuntimeError("SENSITIVE_STS_DETAIL")))
    result = await broker.request_aws_credentials("claude-code", key, "s3-reader")
    _assert_denied_shape(result)
    assert "SENSITIVE_STS_DETAIL" not in result["reason"]
    assert "could not assume role" in result["reason"]
    log_text = log.read_text()
    assert '"decision": "denied"' in log_text
    assert "SENSITIVE_STS_DETAIL" not in log_text


async def test_key_store_failure_fails_closed_generic(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW)

    class _Boom:
        def load(self):
            raise RuntimeError("SENSITIVE_KEY_DETAIL")
    broker.aws_key = _Boom()
    result = await broker.request_aws_credentials("claude-code", key, "s3-reader")
    _assert_denied_shape(result)
    assert "SENSITIVE_KEY_DETAIL" not in result["reason"]
    log_text = log.read_text()
    assert '"decision": "denied"' in log_text
    assert "SENSITIVE_KEY_DETAIL" not in log_text


async def test_tool_registered_with_underscore_name(tmp_path):
    from fastmcp import Client
    broker, key, _log = _make_broker(tmp_path, policies=_ALLOW)
    mcp = build_mcp(broker)
    async with Client(mcp) as client:
        names = [t.name for t in await client.list_tools()]
        assert "aws_credential_request" in names
        res = await client.call_tool("aws_credential_request", {
            "agent": "claude-code", "agent_key": key, "resource": "s3-reader"})
        assert res.data["granted"] is True
