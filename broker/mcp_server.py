from __future__ import annotations

import asyncio
import datetime
import os
import json
import re

import yaml
from fastmcp import FastMCP

from broker import state
from broker.approval import ApprovalQueue, issue_token
from broker.audit import AuditLogger
from broker.config import Config
from broker.credential_store import CredentialStore
from broker.integrations.gmail import INTERNAL_PREFIX
from broker.gmail_tools import register_gmail_tools
from broker.policy_engine import PolicyEngine, PolicyError
from fastmcp.server.dependencies import get_access_token


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
        self.agent_registry = None
        self.policy_revision = 0
        self.total_requests = 0
        self.escalated_requests = 0
        self.start_time = datetime.datetime.now()

    def invalidate_agent_requests(self) -> None:
        self.policy_revision += 1
        self.approvals.reject_agent_requests()

    def _deny_inactive_identity(self, agent: str, credential: str) -> dict:
        self.audit.log(
            agent=agent, credential_requested=credential, policy_matched="identity-check",
            decision="denied", mode=state.read_mode(self.config.state_path), token_expiry=None,
        )
        return {"granted": False, "token": None, "token_expiry": None,
                "value": None, "reason": "Agent identity is no longer active."}

    async def request_credential(self, agent: str, credential: str, *, identity_guard=None) -> dict:
        if identity_guard is not None and not identity_guard():
            return self._deny_inactive_identity(agent, credential)
        self.total_requests += 1
        mode = state.read_mode(self.config.state_path)

        if credential.startswith(INTERNAL_PREFIX):
            self.audit.log(
                agent=agent, credential_requested=credential, policy_matched="internal-only",
                decision="denied", mode=mode, token_expiry=None,
            )
            return {"granted": False, "token": None, "token_expiry": None,
                    "value": None, "reason": "Integration credentials are broker-only."}

        if mode == "manual":
            return await self._escalate(agent, credential, mode, policy_name="manual-mode", identity_guard=identity_guard)

        decision = self.engine.evaluate(agent, credential)
        if decision.auto_approve:
            if identity_guard is not None and not identity_guard():
                return self._deny_inactive_identity(agent, credential)
            return self._grant(agent, credential, mode, decision.policy_name)
        return await self._escalate(agent, credential, mode, decision.policy_name, identity_guard=identity_guard)

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
        self, agent: str, credential: str, mode: str, policy_name: str, identity_guard=None
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
            if identity_guard is not None and not identity_guard():
                return self._deny_inactive_identity(agent, credential)
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

    def list_policies(self) -> list[dict]:
        return self.engine.list_policies()

    def validate_policies(self) -> list[str]:
        return PolicyEngine.validate_file(self.config.policies_path)

    @staticmethod
    def _policy_audit_resource(name: object) -> str:
        if not isinstance(name, str) or not name.strip():
            safe_name = "invalid"
        else:
            safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", name.strip())[:64] or "invalid"
        return f"policy.add:{safe_name}"

    def _audit_policy_add(self, agent: str, resource: str, decision: str) -> None:
        self.audit.log(
            agent=agent, credential_requested=resource, policy_matched="operator-approval",
            decision=decision, mode=state.read_mode(self.config.state_path), token_expiry=None,
        )

    async def add_policy(self, policy: dict, *, identity_guard=None, agent: str = "SYSTEM") -> dict:
        # Hard rule: policy mutation ALWAYS escalates, regardless of mode/policy.
        requested_revision = self.policy_revision
        requested_name = policy.get("name") if isinstance(policy, dict) else None
        resource = self._policy_audit_resource(requested_name)
        try:
            frozen_policy = json.loads(json.dumps(policy))
        except (TypeError, ValueError):
            self._audit_policy_add(agent, resource, "failed")
            return {"added": False, "reason": "policy must be JSON data"}
        if not isinstance(frozen_policy, dict):
            self._audit_policy_add(agent, resource, "failed")
            return {"added": False, "reason": "policy must be an object"}
        frozen_name = frozen_policy.get("name")
        resource = self._policy_audit_resource(frozen_name)
        if identity_guard is not None and not identity_guard():
            self._audit_policy_add(agent, resource, "denied")
            return {"added": False, "reason": f"Agent identity is no longer active; policy '{resource.removeprefix('policy.add:')}' was not added."}
        self.total_requests += 1
        self.escalated_requests += 1
        self._audit_policy_add(agent, resource, "escalated")
        try:
            approved = await self.approvals.submit(
                agent,
                resource,
                timeout=self.config.escalation_timeout_seconds or None,
                details=json.dumps(frozen_policy, ensure_ascii=True, indent=2, sort_keys=True),
            )
        except asyncio.TimeoutError:
            self._audit_policy_add(agent, resource, "expired")
            return {"added": False, "reason": f"policy change escalation timed out for '{resource.removeprefix('policy.add:')}'"}
        if not approved:
            self._audit_policy_add(agent, resource, "denied")
            return {"added": False, "reason": f"policy '{resource.removeprefix('policy.add:')}' change denied by operator"}
        self._audit_policy_add(agent, resource, "approved")
        if requested_revision != self.policy_revision:
            self._audit_policy_add(agent, resource, "denied")
            return {"added": False, "reason": "Policy changed while approval was pending. Request a fresh review."}
        if identity_guard is not None and not identity_guard():
            self._audit_policy_add(agent, resource, "denied")
            return {"added": False, "reason": f"Agent identity is no longer active; policy '{resource.removeprefix('policy.add:')}' was not added."}

        # Build the candidate doc in memory.
        policies_dir = os.path.dirname(os.path.abspath(self.config.policies_path))
        tmp = os.path.join(policies_dir, f".policies_candidate_{os.getpid()}.tmp")
        try:
            with open(self.config.policies_path, "r", encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {"policies": []}
            if not isinstance(doc, dict) or not isinstance(doc.get("policies"), list):
                self._audit_policy_add(agent, resource, "failed")
                return {"added": False, "reason": f"invalid policy file while adding '{resource.removeprefix('policy.add:')}'"}
            doc["policies"].insert(0, frozen_policy)

            # Write and validate the candidate before atomically replacing the file.
            with open(tmp, "w", encoding="utf-8") as fh:
                yaml.safe_dump(doc, fh)
            errors = PolicyEngine.validate_file(tmp)
            if errors:
                self._audit_policy_add(agent, resource, "failed")
                return {"added": False, "reason": f"invalid policy '{resource.removeprefix('policy.add:')}': {errors}"}

            PolicyEngine.from_file(tmp)
            os.replace(tmp, self.config.policies_path)
            self.engine = PolicyEngine.from_file(self.config.policies_path)
            self.invalidate_agent_requests()
        except (OSError, yaml.YAMLError, PolicyError, TypeError, ValueError):
            self._audit_policy_add(agent, resource, "failed")
            return {"added": False, "reason": f"could not apply policy '{resource.removeprefix('policy.add:')}'"}
        finally:
            if os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
        self._audit_policy_add(agent, resource, "completed")
        return {"added": True, "reason": f"policy '{resource.removeprefix('policy.add:')}' added"}

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


def build_mcp(broker: Broker, *, auth=None, gmail_tools=None, trusted_agent: str = "agentgate-local") -> FastMCP:
    mcp = FastMCP("AgentGate", auth=auth, mask_error_details=True)

    def identity(supplied: str | None):
        """Resolve identity from the authenticated token or trusted launcher config."""
        if broker.agent_registry is not None:
            try:
                access = get_access_token()
            except Exception:
                return None, None
            token = access.token if access is not None else None
            metadata = broker.agent_registry.authenticate(token) if token else None
            if metadata is None or access.client_id != metadata["id"]:
                return None, None
            agent_id = metadata["id"]
            if supplied is not None and supplied != agent_id:
                return None, None
            def still_active() -> bool:
                current = broker.agent_registry.authenticate(token)
                return current is not None and current["id"] == agent_id
            return agent_id, still_active
        if supplied is not None and supplied != trusted_agent:
            return None, None
        return trusted_agent, lambda: True

    broker.resolve_agent_identity = identity

    def unauthorized():
        return {"ok": False, "reason": "Authenticated agent identity is missing, inactive, or does not match the request."}

    @mcp.tool(name="credential.request")
    async def credential_request(credential: str, agent: str | None = None) -> dict:
        resolved, guard = identity(agent)
        if resolved is None:
            return {"granted": False, "token": None, "token_expiry": None, "value": None,
                    "reason": "Authenticated agent identity is missing, inactive, or does not match the request."}
        return await broker.request_credential(resolved, credential, identity_guard=guard)

    @mcp.tool(name="policy.list")
    def policy_list(agent: str | None = None) -> list[dict]:
        if identity(agent)[0] is None:
            return []
        return broker.list_policies()

    @mcp.tool(name="policy.validate")
    def policy_validate(agent: str | None = None) -> dict:
        if identity(agent)[0] is None:
            return {"valid": False, "errors": ["Authenticated agent identity is missing, inactive, or does not match the request."]}
        errors = broker.validate_policies()
        return {"valid": not errors, "errors": errors}

    @mcp.tool(name="policy.add")
    async def policy_add(policy: dict, agent: str | None = None) -> dict:
        resolved, guard = identity(agent)
        if resolved is None:
            return {"added": False, "reason": unauthorized()["reason"]}
        return await broker.add_policy(policy, identity_guard=guard, agent=resolved)

    @mcp.tool(name="broker.status")
    def broker_status(agent: str | None = None) -> dict:
        if identity(agent)[0] is None:
            return {}
        return broker.status()

    if gmail_tools is None:
        register_gmail_tools(mcp, broker, identity_resolver=identity)
    else:
        register_gmail_tools(mcp, broker, tools=gmail_tools, identity_resolver=identity)
    return mcp
