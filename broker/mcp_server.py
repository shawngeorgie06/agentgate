from __future__ import annotations

import asyncio
import datetime
import os
import sys

import yaml
from fastmcp import FastMCP

from broker import oauth, state
from broker.approval import ApprovalQueue
from broker.audit import AuditLogger
from broker.config import Config
from broker.connection_store import ConnectionStore
from broker.credential_store import CredentialDecryptionError, CredentialStore
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
        connections: ConnectionStore | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self.engine = engine
        self.audit = audit
        self.approvals = approvals
        self.connections = connections
        self._token_cache: dict[str, dict] = {}
        self._policies_mtime = self._policies_file_mtime()
        self.total_requests = 0
        self.escalated_requests = 0
        self.start_time = datetime.datetime.now(datetime.timezone.utc)

    def _policies_file_mtime(self) -> float | None:
        try:
            return os.path.getmtime(self.config.policies_path)
        except OSError:
            return None

    def _current_engine(self) -> PolicyEngine:
        """Reload policies when the file changes on disk, so hand-edits take
        effect without a restart. An invalid edit keeps the last valid engine
        (warned once per change) rather than taking the broker down."""
        mtime = self._policies_file_mtime()
        if mtime != self._policies_mtime:
            self._policies_mtime = mtime
            try:
                self.engine = PolicyEngine.from_file(self.config.policies_path)
            except PolicyError as exc:
                print(
                    f"[AgentGate] WARNING: policies file invalid, keeping previous "
                    f"policies: {exc}",
                    file=sys.stderr,
                )
        return self.engine

    async def request_credential(self, agent: str, credential: str) -> dict:
        self.total_requests += 1
        mode = state.read_mode(self.config.state_path)

        if mode == "manual":
            return await self._escalate(agent, credential, mode, policy_name="manual-mode")

        decision = self._current_engine().evaluate(agent, credential)
        if decision.auto_approve:
            return self._grant(agent, credential, mode, decision.policy_name)
        if not decision.escalate:
            # Hard deny: the policy explicitly opted out of bothering the
            # operator. Audited, immediate, no pending approval created.
            self.audit.log(
                agent=agent, credential_requested=credential,
                policy_matched=decision.policy_name, decision="denied",
                mode=mode, token_expiry=None,
            )
            return {
                "granted": False,
                "value": None,
                "reason": f"denied by policy '{decision.policy_name}'",
            }
        return await self._escalate(agent, credential, mode, decision.policy_name)

    def _grant(self, agent: str, credential: str, mode: str, policy_name: str) -> dict:
        # Both failure shapes fail closed with an audit row and a structured
        # denial — never a raw exception (which would carry no audit entry and
        # could leak internal detail to the agent).
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
                "value": None,
                "reason": f"unknown credential '{credential}'",
            }
        except CredentialDecryptionError:
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
                "value": None,
                "reason": f"could not read credential '{credential}'",
            }
        self.audit.log(
            agent=agent,
            credential_requested=credential,
            policy_matched=policy_name,
            decision="approved",
            mode=mode,
            token_expiry=None,
        )
        return {
            "granted": True,
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
            "value": None,
            "reason": "denied by operator",
        }

    async def request_token(self, agent: str, connection: str) -> dict:
        self.total_requests += 1
        mode = state.read_mode(self.config.state_path)

        if mode == "manual":
            return await self._escalate_token(agent, connection, mode, "manual-mode")

        decision = self._current_engine().evaluate(agent, connection)
        if decision.auto_approve:
            return await self._grant_token(agent, connection, mode, decision.policy_name)
        if not decision.escalate:
            self.audit.log(
                agent=agent, credential_requested=connection,
                policy_matched=decision.policy_name, decision="denied",
                mode=mode, token_expiry=None,
            )
            return {"granted": False, "access_token": None, "token_expiry": None,
                    "scopes": None, "reason": f"denied by policy '{decision.policy_name}'"}
        return await self._escalate_token(agent, connection, mode, decision.policy_name)

    async def _grant_token(self, agent: str, connection: str, mode: str, policy_name: str) -> dict:
        # Fail closed if no connections store is configured, or the name is unknown.
        # Guard None explicitly so a real error inside ConnectionStore.get (e.g. a
        # corrupt store) is NOT misclassified as "unknown connection".
        if self.connections is None:
            conn = None
        else:
            try:
                conn = self.connections.get(connection)
            except KeyError:
                conn = None
        if conn is None:
            self.audit.log(
                agent=agent, credential_requested=connection, policy_matched=policy_name,
                decision="denied", mode=mode, token_expiry=None,
            )
            return {"granted": False, "access_token": None, "token_expiry": None,
                    "scopes": None, "reason": f"unknown connection '{connection}'"}

        token = self._cached_token(connection)
        if token is None:
            # A failed refresh must fail closed with an audited denial — never a raw
            # exception (which would carry no audit row and could leak provider detail).
            try:
                preset = oauth.get_preset(conn.provider)
                fresh = await oauth.refresh_access_token(
                    token_url=preset.token_url, client_id=conn.client_id,
                    client_secret=conn.client_secret, refresh_token=conn.refresh_token,
                )
            except oauth.OAuthError:
                self.audit.log(
                    agent=agent, credential_requested=connection, policy_matched=policy_name,
                    decision="denied", mode=mode, token_expiry=None,
                )
                return {"granted": False, "access_token": None, "token_expiry": None,
                        "scopes": None, "reason": f"could not mint token for '{connection}'"}
            # Fall back to stored scopes when the provider doesn't echo them on refresh.
            token = {"access_token": fresh["access_token"], "expires_at": fresh["expires_at"],
                     "scopes": fresh["scopes"] if fresh["scopes"] else conn.scopes}
            self._token_cache[connection] = token

        self.audit.log(
            agent=agent, credential_requested=connection, policy_matched=policy_name,
            decision="approved", mode=mode, token_expiry=token["expires_at"],
            scopes=token["scopes"],
        )
        return {"granted": True, "access_token": token["access_token"],
                "token_expiry": token["expires_at"], "scopes": token["scopes"],
                "reason": f"auto-approved by policy '{policy_name}'"}

    def _cached_token(self, connection: str) -> dict | None:
        token = self._token_cache.get(connection)
        if token is None:
            return None
        try:
            expires = datetime.datetime.fromisoformat(token["expires_at"])
        except (ValueError, TypeError):
            return None
        if datetime.datetime.now(datetime.timezone.utc) >= expires - datetime.timedelta(seconds=60):
            self._token_cache.pop(connection, None)
            return None
        return token

    async def _escalate_token(self, agent: str, connection: str, mode: str, policy_name: str) -> dict:
        self.escalated_requests += 1
        self.audit.log(
            agent=agent, credential_requested=connection, policy_matched=policy_name,
            decision="escalated", mode=mode, token_expiry=None,
        )
        try:
            approved = await self.approvals.submit(
                agent, connection, timeout=self.config.escalation_timeout_seconds or None
            )
        except asyncio.TimeoutError:
            self.audit.log(
                agent=agent, credential_requested=connection, policy_matched=policy_name,
                decision="expired", mode=mode, token_expiry=None,
            )
            return {"granted": False, "access_token": None, "token_expiry": None,
                    "scopes": None, "reason": "escalation timed out"}
        if approved:
            return await self._grant_token(agent, connection, mode, f"manual:{policy_name}")
        self.audit.log(
            agent=agent, credential_requested=connection, policy_matched=policy_name,
            decision="denied", mode=mode, token_expiry=None,
        )
        return {"granted": False, "access_token": None, "token_expiry": None,
                "scopes": None, "reason": "denied by operator"}

    def list_policies(self) -> list[dict]:
        return self._current_engine().list_policies()

    def validate_policies(self) -> list[str]:
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
        self._policies_mtime = self._policies_file_mtime()
        return {"added": True, "reason": f"policy '{policy.get('name')}' added"}

    def status(self) -> dict:
        return {
            "mode": state.read_mode(self.config.state_path),
            "policies": len(self.engine.list_policies()),
            "requests": self.total_requests,
            "escalated": self.escalated_requests,
            "uptime_seconds": int(
                (datetime.datetime.now(datetime.timezone.utc) - self.start_time).total_seconds()
            ),
        }


def build_mcp(broker: Broker) -> FastMCP:
    mcp = FastMCP("AgentGate")

    @mcp.tool(name="credential.request")
    async def credential_request(agent: str, credential: str) -> dict:
        return await broker.request_credential(agent, credential)

    @mcp.tool(name="policy.list")
    def policy_list() -> list[dict]:
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

    @mcp.tool(name="token.request")
    async def token_request(agent: str, connection: str) -> dict:
        return await broker.request_token(agent, connection)

    return mcp
