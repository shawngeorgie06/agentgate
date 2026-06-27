from __future__ import annotations

import asyncio
import datetime
import os
from typing import List

import yaml
from fastmcp import FastMCP

from broker import state
from broker.approval import ApprovalQueue, issue_token
from broker.audit import AuditLogger
from broker.config import Config
from broker.credential_store import CredentialStore
from broker.policy_engine import PolicyEngine, PolicyError


class Broker:
    def __init__(
        self,
        *,
        config: Config,
        store: CredentialStore,
        engine: PolicyEngine,
        audit: AuditLogger,
        approvals: ApprovalQueue,
    ) -> None:
        self.config = config
        self.store = store
        self.engine = engine
        self.audit = audit
        self.approvals = approvals
        self.total_requests = 0
        self.escalated_requests = 0
        self.start_time = datetime.datetime.now()

    async def request_credential(self, agent: str, credential: str) -> dict:
        self.total_requests += 1
        mode = state.read_mode(self.config.state_path)

        if mode == "manual":
            return await self._escalate(agent, credential, mode, policy_name="manual-mode")

        decision = self.engine.evaluate(agent, credential)
        if decision.auto_approve:
            return self._grant(agent, credential, mode, decision.policy_name)
        return await self._escalate(agent, credential, mode, decision.policy_name)

    def _grant(self, agent: str, credential: str, mode: str, policy_name: str) -> dict:
        try:
            value = self.store.retrieve(credential)
        except KeyError:
            self.audit.log(
                agent=agent,
                credential_requested=credential,
                policy_matched=policy_name,
                decision="denied",
                mode=mode,
                token_expiry=None,
            )
            return {
                "granted": False,
                "token": None,
                "token_expiry": None,
                "value": None,
                "reason": f"unknown credential '{credential}'",
            }
        token, expiry = issue_token(self.config.token_ttl_minutes)
        self.audit.log(
            agent=agent,
            credential_requested=credential,
            policy_matched=policy_name,
            decision="approved",
            mode=mode,
            token_expiry=expiry,
        )
        return {
            "granted": True,
            "token": token,
            "token_expiry": expiry,
            "value": value,
            "reason": f"auto-approved by policy '{policy_name}'",
        }

    async def _escalate(
        self, agent: str, credential: str, mode: str, policy_name: str
    ) -> dict:
        self.escalated_requests += 1
        self.audit.log(
            agent=agent,
            credential_requested=credential,
            policy_matched=policy_name,
            decision="escalated",
            mode=mode,
            token_expiry=None,
        )
        try:
            approved = await self.approvals.submit(
                agent, credential, timeout=self.config.escalation_timeout_seconds or None
            )
        except asyncio.TimeoutError:
            self.audit.log(
                agent=agent,
                credential_requested=credential,
                policy_matched=policy_name,
                decision="expired",
                mode=mode,
                token_expiry=None,
            )
            return {
                "granted": False,
                "token": None,
                "token_expiry": None,
                "value": None,
                "reason": "escalation timed out",
            }
        if approved:
            return self._grant(agent, credential, mode, f"manual:{policy_name}")
        self.audit.log(
            agent=agent,
            credential_requested=credential,
            policy_matched=policy_name,
            decision="denied",
            mode=mode,
            token_expiry=None,
        )
        return {
            "granted": False,
            "token": None,
            "token_expiry": None,
            "value": None,
            "reason": "denied by operator",
        }

    def list_policies(self) -> List[dict]:
        return self.engine.list_policies()

    def validate_policies(self) -> List[str]:
        return PolicyEngine.validate_file(self.config.policies_path)

    async def add_policy(self, policy: dict) -> dict:
        # Hard rule: policy mutation ALWAYS escalates, regardless of mode/policy.
        try:
            approved = await self.approvals.submit(
                "SYSTEM",
                f"policy.add:{policy.get('name')}",
                timeout=self.config.escalation_timeout_seconds or None,
            )
        except asyncio.TimeoutError:
            return {"added": False, "reason": "policy change escalation timed out"}
        if not approved:
            return {"added": False, "reason": "policy change denied by operator"}

        # Build the candidate doc in memory.
        with open(self.config.policies_path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {"policies": []}
        doc["policies"].insert(0, policy)

        # Write the candidate to a temp file in the SAME directory (atomic replace).
        policies_dir = os.path.dirname(os.path.abspath(self.config.policies_path))
        tmp = os.path.join(policies_dir, f".policies_candidate_{os.getpid()}.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            yaml.safe_dump(doc, fh)

        # Validate BEFORE touching the real file.
        errors = PolicyEngine.validate_file(tmp)
        if errors:
            os.remove(tmp)
            return {"added": False, "reason": f"invalid policy: {errors}"}

        # Validation passed — atomically replace the real file and reload the engine.
        os.replace(tmp, self.config.policies_path)
        self.engine = PolicyEngine.from_file(self.config.policies_path)
        return {"added": True, "reason": f"policy '{policy.get('name')}' added"}

    def status(self) -> dict:
        return {
            "mode": state.read_mode(self.config.state_path),
            "policies": len(self.engine.list_policies()),
            "requests": self.total_requests,
            "escalated": self.escalated_requests,
            "uptime_seconds": int(
                (datetime.datetime.now() - self.start_time).total_seconds()
            ),
        }


def build_mcp(broker: Broker) -> FastMCP:
    mcp = FastMCP("AgentGate")

    @mcp.tool(name="credential.request")
    async def credential_request(agent: str, credential: str) -> dict:
        return await broker.request_credential(agent, credential)

    @mcp.tool(name="policy.list")
    def policy_list() -> List[dict]:
        return broker.list_policies()

    @mcp.tool(name="policy.validate")
    def policy_validate() -> dict:
        errors = broker.validate_policies()
        return {"valid": not errors, "errors": errors}

    @mcp.tool(name="policy.add")
    async def policy_add(policy: dict) -> dict:
        return await broker.add_policy(policy)

    @mcp.tool(name="broker.status")
    def broker_status() -> dict:
        return broker.status()

    return mcp
