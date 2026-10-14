"""Shared policy, temporary lease, approval, and dispatch checks."""
from __future__ import annotations

import asyncio
from typing import Any, Callable

from broker import state


class AccessError(Exception):
    """A captured authorization is no longer valid at the provider boundary."""


_ALWAYS_MANUAL = {"gmail:send", "github:write"}


class AccessController:
    def __init__(self, broker):
        self.broker = broker

    def _grant(self, agent: str, resource: str):
        grants = getattr(self.broker, "temporary_grants", None)
        return grants.active_grant(agent, resource) if grants is not None else None

    def _identity_active(self, agent: str) -> bool:
        registry = getattr(self.broker, "agent_registry", None)
        if registry is None:
            registry = getattr(getattr(self.broker, "temporary_grants", None), "registry", None)
        if registry is None:
            return True
        return any(item["id"] == agent and item["status"] == "active" for item in registry.list_agents())

    def _audit(self, agent: str, resource: str, policy: str, mode: str, decision: str):
        try:
            self.broker.audit.log(agent=agent, credential_requested=resource,
                                  policy_matched=policy, decision=decision,
                                  mode=mode, token_expiry=None)
        except (AttributeError, TypeError):
            pass

    def access_guard(self, agent: str, resource: str, identity_guard=None, *, trusted_operator=False) -> Callable[[], bool]:
        revision = self.broker.policy_revision
        captured_mode = state.read_mode(self.broker.config.state_path)
        initial = self._grant(agent, resource)
        signature = ((initial["id"], initial["permission"], initial["expires_at"]) if initial else None)

        def baseline_signature():
            decision = self.broker.engine.evaluate(agent, resource)
            return (decision.policy_name, decision.auto_approve, decision.escalate)
        baseline = baseline_signature() if not trusted_operator and initial is None else None

        def active() -> bool:
            if not trusted_operator and not self._identity_active(agent):
                return False
            if identity_guard is not None and not identity_guard():
                return False
            if not trusted_operator and state.read_mode(self.broker.config.state_path) != captured_mode:
                return False
            if self.broker.policy_revision != revision:
                return False
            current = self._grant(agent, resource)
            current_signature = ((current["id"], current["permission"], current["expires_at"]) if current else None)
            # Any grant mutation, expiry, or agent deactivation invalidates queued work.
            return (current_signature == signature and
                    (baseline is None or baseline_signature() == baseline))
        return active

    async def authorize(self, agent: str, resource: str, details=None, identity_guard=None, *,
                        trusted_operator: bool = False, require_approval: bool = False) -> bool:
        mode = state.read_mode(self.broker.config.state_path)
        if not trusted_operator and not self._identity_active(agent):
            self._audit(agent, resource, "identity-check", mode, "denied")
            return False
        if identity_guard is not None and not identity_guard():
            self._audit(agent, resource, "identity-check", mode, "denied")
            return False
        self.broker.total_requests += 1
        decision = self.broker.engine.evaluate(agent, resource)
        policy = decision.policy_name
        if trusted_operator and resource not in _ALWAYS_MANUAL and not require_approval:
            self._audit(agent, resource, "trusted-operator", mode, "approved")
            return True
        grant = self._grant(agent, resource)
        # A baseline hard deny remains in force unless the operator grants an
        # explicit, temporary lease for this exact resource.
        if not trusted_operator and grant is None and not decision.auto_approve and not decision.escalate:
            self._audit(agent, resource, policy, mode, "denied")
            return False
        if trusted_operator:
            decision_auto = True
        else:
            decision_auto = decision.auto_approve
        permission = grant["permission"] if grant else ("allow" if decision_auto else "ask")
        manual = (mode != "auto" or permission == "ask" or resource in _ALWAYS_MANUAL or require_approval)
        if not manual:
            self._audit(agent, resource, policy, mode, "approved")
            return True

        self.broker.escalated_requests += 1
        self._audit(agent, resource, policy, mode, "escalated")
        try:
            approved = await self.broker.approvals.submit(
                agent, resource,
                timeout=self.broker.config.escalation_timeout_seconds or None,
                details=details,
            )
        except asyncio.TimeoutError:
            self._audit(agent, resource, policy, mode, "expired")
            return False
        if approved and identity_guard is not None and not identity_guard():
            approved = False
        self._audit(agent, resource, policy, mode, "approved" if approved else "denied")
        return approved

    async def execute(self, provider, agent: str, resource: str, operation: str, *,
                      identity_guard=None, details=None, require_approval=False, **arguments) -> dict[str, Any]:
        guard = self.access_guard(agent, resource, identity_guard)
        if not await self.authorize(agent, resource, details, guard, require_approval=require_approval):
            return {"ok": False, "reason": "Access denied, approval timed out, or captured access changed."}

        def before_dispatch():
            if not guard():
                raise AccessError("Agent access is no longer active, or permissions changed or expired.")
        try:
            data = await asyncio.to_thread(provider.call, operation, before_dispatch=before_dispatch, **arguments)
        except AccessError as exc:
            mode = state.read_mode(self.broker.config.state_path)
            self._audit(agent, resource, operation, mode, "denied")
            return {"ok": False, "reason": str(exc)}
        except Exception as exc:
            # Providers may expose an explicitly sanitized message; never return arbitrary exception text.
            safe = getattr(exc, "safe_message", None)
            reason = safe if isinstance(safe, str) and safe else "Provider operation failed."
            self._audit(agent, resource, operation, state.read_mode(self.broker.config.state_path), "failed")
            return {"ok": False, "reason": reason}
        self._audit(agent, resource, operation, state.read_mode(self.broker.config.state_path), "completed")
        return {"ok": True, "data": data}
