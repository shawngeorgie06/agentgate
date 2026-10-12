"""Trusted identity, policy, and approval boundary for GitHub MCP tools."""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import threading
from typing import TYPE_CHECKING

from fastmcp import FastMCP

from broker.access import AccessController, AccessError
from broker.integrations.github import GitHub, GitHubError, INTERNAL_PREFIX

if TYPE_CHECKING:
    from broker.mcp_server import Broker


_REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


class GitHubTools:
    def __init__(self, broker: Broker, github: GitHub):
        self.broker = broker
        self.github = github
        self.access = AccessController(broker)
        self._attempt_lock = threading.RLock()
        self._ledger_name = INTERNAL_PREFIX + "github-attempts"
        try:
            stored = json.loads(broker.store.retrieve(self._ledger_name))
            self._attempts = set(stored) if isinstance(stored, list) else set()
        except (KeyError, ValueError, TypeError):
            self._attempts: set[str] = set()

    def _audit(self, agent: str, resource: str, operation: str, decision: str):
        from broker import state
        self.broker.audit.log(
            agent=agent, credential_requested=resource, policy_matched=operation,
            decision=decision, mode=state.read_mode(self.broker.config.state_path), token_expiry=None,
        )

    async def execute(self, agent: str, resource: str, operation: str, *, identity_guard=None, **arguments) -> dict:
        return await self.access.execute(self.github, agent, resource, operation,
                                         identity_guard=identity_guard, **arguments)

    @staticmethod
    def _validate_request_id(request_id: object) -> str:
        if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
            raise GitHubError("request_id must contain 16 to 128 URL-safe letters, numbers, underscores, or hyphens.")
        return hashlib.sha256(request_id.encode("utf-8")).hexdigest()

    async def create_issue(self, agent: str, *, owner: str, repo: str, title: str,
                           body: str = "", request_id: str, identity_guard=None) -> dict:
        try:
            attempt_key = self._validate_request_id(request_id)
        except GitHubError as exc:
            return {"ok": False, "reason": str(exc)}

        # A stable caller request id makes duplicate tool submissions safe across
        # reconnects and process restarts; only its hash is persisted.
        with self._attempt_lock:
            if attempt_key in self._attempts:
                return {"ok": False, "reason": "This issue request already has an attempt. Check GitHub before retrying."}

        try:
            frozen = json.loads(json.dumps({
                "owner": owner, "repo": repo, "title": title, "body": body,
            }))
        except (TypeError, ValueError):
            return {"ok": False, "reason": "Issue fields must be JSON text values."}
        if not all(isinstance(frozen.get(key), str) for key in ("owner", "repo", "title", "body")):
            return {"ok": False, "reason": "Issue fields must be text values."}
        details = json.dumps(frozen, ensure_ascii=True, indent=2, sort_keys=True)
        guard = self.access.access_guard(agent, "github:write", identity_guard)
        if not await self.access.authorize(agent, "github:write", details, guard, require_approval=True):
            return {"ok": False, "reason": "Issue creation denied or approval timed out."}

        dispatch_started = False

        def before_dispatch():
            nonlocal dispatch_started
            if not guard():
                raise AccessError("Agent access is no longer active, or permissions changed or expired.")
            # Persist immediately before the single POST. If transport outcome is
            # uncertain, the marker stays so caller retries cannot duplicate it.
            with self._attempt_lock:
                if attempt_key in self._attempts:
                    raise GitHubError("This issue request already has an attempt. Check GitHub before retrying.")
                self._attempts.add(attempt_key)
                self.broker.store.store(self._ledger_name, json.dumps(sorted(self._attempts)))
                dispatch_started = True

        try:
            data = await asyncio.to_thread(
                self.github.call, "create_issue", before_dispatch=before_dispatch, **frozen,
            )
        except AccessError:
            self._audit(agent, "github:write", "create_issue", "denied")
            return {"ok": False, "reason": "Agent access is no longer active, or permissions changed or expired."}
        except GitHubError as exc:
            if dispatch_started:
                reason = str(exc) + " The result may be uncertain; check GitHub before retrying."
            else:
                reason = str(exc)
            self._audit(agent, "github:write", "create_issue", "failed")
            return {"ok": False, "reason": reason}
        except Exception:
            self._audit(agent, "github:write", "create_issue", "failed")
            suffix = " The result may be uncertain; check GitHub before retrying." if dispatch_started else ""
            return {"ok": False, "reason": "GitHub issue creation failed." + suffix}
        self._audit(agent, "github:write", "create_issue", "completed")
        return {"ok": True, "data": data}


def register_github_tools(mcp: FastMCP, broker: Broker, github: GitHub | None = None, *,
                          tools: GitHubTools | None = None, identity_resolver=None,
                          trusted_agent: str | None = None) -> GitHubTools:
    tools = tools or GitHubTools(broker, github or GitHub(broker.store))
    if identity_resolver is None and trusted_agent is None:
        raise ValueError("GitHub tools require a trusted identity resolver.")

    def resolve_agent(supplied: str | None):
        if identity_resolver is not None:
            return identity_resolver(supplied)
        if supplied is not None and supplied != trusted_agent:
            return None, None
        return trusted_agent, lambda: True

    def missing_identity():
        return {"ok": False, "reason": "Authenticated agent identity is missing, inactive, or does not match the request."}

    @mcp.tool(name="github.account")
    async def account(agent: str | None = None) -> dict:
        """Return the authenticated GitHub login and numeric account ID."""
        resolved, guard = resolve_agent(agent)
        if resolved is None:
            return missing_identity()
        return await tools.execute(resolved, "github:read", "account", identity_guard=guard)

    @mcp.tool(name="github.repos")
    async def repos(per_page: int = 30, page: int = 1, agent: str | None = None) -> dict:
        """List a bounded page of repositories visible to the connected account."""
        resolved, guard = resolve_agent(agent)
        if resolved is None:
            return missing_identity()
        return await tools.execute(resolved, "github:read", "repos", identity_guard=guard,
                                   per_page=per_page, page=page)

    @mcp.tool(name="github.repo")
    async def repo(owner: str, repo: str, agent: str | None = None) -> dict:
        """Read safe metadata for one owner and repository."""
        resolved, guard = resolve_agent(agent)
        if resolved is None:
            return missing_identity()
        return await tools.execute(resolved, "github:read", "repo", identity_guard=guard,
                                   owner=owner, repo=repo)

    @mcp.tool(name="github.read_file")
    async def read_file(owner: str, repo: str, path: str, ref: str | None = None,
                        agent: str | None = None) -> dict:
        """Read a UTF-8 repository file up to 1 MiB."""
        resolved, guard = resolve_agent(agent)
        if resolved is None:
            return missing_identity()
        return await tools.execute(resolved, "github:read", "read_file", identity_guard=guard,
                                   owner=owner, repo=repo, path=path, ref=ref)

    @mcp.tool(name="github.issues")
    async def issues(owner: str, repo: str, state: str = "open", limit: int = 30,
                     page: int = 1, agent: str | None = None) -> dict:
        """List a bounded page of repository issues."""
        resolved, guard = resolve_agent(agent)
        if resolved is None:
            return missing_identity()
        return await tools.execute(resolved, "github:read", "issues", identity_guard=guard,
                                   owner=owner, repo=repo, state=state, limit=limit, page=page)

    @mcp.tool(name="github.create_issue")
    async def create_issue(owner: str, repo: str, title: str, body: str = "",
                           request_id: str = "", agent: str | None = None) -> dict:
        """Create one issue after explicit operator approval of the frozen title and body."""
        resolved, guard = resolve_agent(agent)
        if resolved is None:
            return missing_identity()
        return await tools.create_issue(resolved, owner=owner, repo=repo, title=title,
                                        body=body, request_id=request_id, identity_guard=guard)

    return tools
