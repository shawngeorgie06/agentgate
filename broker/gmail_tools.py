"""Policy and approval boundaries for Gmail MCP tools."""
from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING

from fastmcp import FastMCP

from broker import state
from broker.access import AccessController, AccessError
from broker.integrations.gmail import Gmail, GmailError, INTERNAL_PREFIX

if TYPE_CHECKING:
    from broker.mcp_server import Broker


class GmailTools:
    def __init__(self, broker: Broker, gmail: Gmail):
        self.broker = broker
        self.gmail = gmail
        self.access = AccessController(broker)
        self._send_lock = asyncio.Lock()
        self._ledger_name = INTERNAL_PREFIX + 'gmail-send-attempts'
        try:
            self._sent_drafts = set(json.loads(broker.store.retrieve(self._ledger_name)))
        except KeyError:
            self._sent_drafts: set[str] = set()

    def audit(self, agent: str, resource: str, policy: str, mode: str, decision: str):
        self.broker.audit.log(
            agent=agent, credential_requested=resource, policy_matched=policy,
            decision=decision, mode=mode, token_expiry=None,
        )

    def access_guard(self, agent: str, resource: str, identity_guard=None, *, trusted_operator=False):
        return self.access.access_guard(agent, resource, identity_guard, trusted_operator=trusted_operator)

    async def authorize(self, agent: str, resource: str, details: str | None = None,
                        identity_guard=None, *, trusted_operator: bool = False,
                        require_approval: bool = False) -> bool:
        return await self.access.authorize(agent, resource, details, identity_guard,
                                           trusted_operator=trusted_operator,
                                           require_approval=require_approval)

    async def execute(self, agent: str, resource: str, operation: str, *, identity_guard=None, **arguments) -> dict:
        identity_guard = self.access_guard(agent, resource, identity_guard)
        if not await self.authorize(agent, resource, identity_guard=identity_guard):
            return {'ok': False, 'reason': 'Access denied or approval timed out.'}
        def check_active():
            if identity_guard is not None and not identity_guard():
                raise IdentityError()
        try:
            data = await asyncio.to_thread(self.gmail.call, operation, before_dispatch=check_active, **arguments)
        except AccessError:
            self.audit(agent, resource, operation, state.read_mode(self.broker.config.state_path), 'denied')
            return {'ok': False, 'reason': 'Agent access is no longer active, or permissions changed.'}
        except GmailError as exc:
            self.audit(agent, resource, operation, state.read_mode(self.broker.config.state_path), 'failed')
            return {'ok': False, 'reason': str(exc)}
        self.audit(agent, resource, operation, state.read_mode(self.broker.config.state_path), 'completed')
        return {'ok': True, 'data': data}

    async def send_draft(self, agent: str, draft_id: str, *, identity_guard=None,
                         trusted_operator: bool = False) -> dict:
        if trusted_operator:
            agent, identity_guard = 'operator', None
        async with self._send_lock:
            draft_guard = self.access_guard(agent, 'gmail:draft', identity_guard,
                                            trusted_operator=trusted_operator)
            send_guard = self.access_guard(agent, 'gmail:send', identity_guard,
                                           trusted_operator=trusted_operator)
            identity_guard = send_guard
            if identity_guard is not None and not identity_guard():
                self.audit(agent, 'gmail:send', 'identity-check', state.read_mode(self.broker.config.state_path), 'denied')
                return {'ok': False, 'reason': 'Agent access is no longer active, or permissions changed.'}
            if draft_id in self._sent_drafts:
                return {'ok': False, 'reason': 'This draft already has a send attempt. Check Gmail before creating another draft.'}
            # Access to draft contents must itself be authorized.
            if not await self.authorize(agent, 'gmail:draft', identity_guard=draft_guard,
                                        trusted_operator=trusted_operator):
                return {'ok': False, 'reason': 'Draft access denied or approval timed out.'}
            try:
                snapshot = await asyncio.to_thread(self.gmail.call, 'snapshot', before_dispatch=_identity_callback(draft_guard), draft_id=draft_id)
            except IdentityError:
                self.audit(agent, 'gmail:draft', 'snapshot', state.read_mode(self.broker.config.state_path), 'denied')
                return {'ok': False, 'reason': 'Agent access is no longer active, or permissions changed.'}
            except GmailError as exc:
                return {'ok': False, 'reason': str(exc)}
            details = json.dumps({'draft_id': draft_id, **snapshot['preview']}, ensure_ascii=True, indent=2)
            if not await self.authorize(agent, 'gmail:send', details=details, identity_guard=identity_guard,
                                        trusted_operator=trusted_operator, require_approval=True):
                return {'ok': False, 'reason': 'Send denied or approval timed out.'}
            # Mark before dispatch: network failures can leave delivery uncertain.
            # Never retry a non-idempotent send automatically.
            self._sent_drafts.add(draft_id)
            self.broker.store.store(self._ledger_name, json.dumps(sorted(self._sent_drafts)))
            try:
                data = await asyncio.to_thread(self.gmail.call, 'send', before_dispatch=_identity_callback_all(draft_guard, send_guard), snapshot=snapshot)
            except IdentityError:
                # Revoke the in-memory marker only when no provider dispatch occurred.
                # Gmail's before_dispatch runs immediately at the dispatch boundary.
                self._sent_drafts.discard(draft_id)
                self.broker.store.store(self._ledger_name, json.dumps(sorted(self._sent_drafts)))
                self.audit(agent, 'gmail:send', 'send', state.read_mode(self.broker.config.state_path), 'denied')
                return {'ok': False, 'reason': 'Agent access is no longer active, or permissions changed.'}
            except GmailError as exc:
                self.audit(agent, 'gmail:send', 'send', state.read_mode(self.broker.config.state_path), 'failed')
                return {'ok': False, 'reason': str(exc) + ' Delivery may be uncertain; check Gmail before retrying.'}
            self.audit(agent, 'gmail:send', 'send', state.read_mode(self.broker.config.state_path), 'completed')
            return {'ok': True, 'data': data, 'draft_retained': True}


class IdentityError(AccessError):
    """Raised inside a provider worker when a captured identity is no longer active."""


def _identity_callback(identity_guard):
    def check():
        if identity_guard is not None and not identity_guard():
            raise IdentityError()
    return check


def _identity_callback_all(*guards):
    def check():
        if any(guard is not None and not guard() for guard in guards):
            raise IdentityError()
    return check


def register_gmail_tools(mcp: FastMCP, broker: Broker, gmail: Gmail | None = None, *,
                         tools: GmailTools | None = None, identity_resolver=None,
                         trusted_agent: str | None = None) -> GmailTools:
    tools = tools or GmailTools(broker, gmail or Gmail(broker.store))

    def resolve_agent(supplied: str | None):
        if identity_resolver is not None:
            return identity_resolver(supplied)
        if trusted_agent is None or (supplied is not None and supplied != trusted_agent):
            return None, None
        return trusted_agent, lambda: True

    @mcp.tool(name='gmail.search')
    async def search(query: str, limit: int = 20, page_token: str | None = None, agent: str | None = None) -> dict:
        """Search Gmail using its query syntax. Returns message IDs and pagination."""
        resolved, guard = resolve_agent(agent)
        if resolved is None:
            return {'ok': False, 'reason': 'Authenticated agent identity is missing, inactive, or does not match the request.'}
        return await tools.execute(resolved, 'gmail:read', 'search', identity_guard=guard, query=query, limit=limit, page_token=page_token)

    @mcp.tool(name='gmail.read')
    async def read(message_id: str, agent: str | None = None) -> dict:
        """Read email headers and body; attachment contents are not returned."""
        resolved, guard = resolve_agent(agent)
        if resolved is None:
            return {'ok': False, 'reason': 'Authenticated agent identity is missing, inactive, or does not match the request.'}
        return await tools.execute(resolved, 'gmail:read', 'read', identity_guard=guard, message_id=message_id)

    @mcp.tool(name='gmail.draft')
    async def draft(to: str, subject: str, body: str, cc: str = '', bcc: str = '', agent: str | None = None) -> dict:
        """Create a plain-text Gmail draft. This does not send email."""
        resolved, guard = resolve_agent(agent)
        if resolved is None:
            return {'ok': False, 'reason': 'Authenticated agent identity is missing, inactive, or does not match the request.'}
        return await tools.execute(resolved, 'gmail:draft', 'draft', identity_guard=guard, to=to, subject=subject, body=body, cc=cc, bcc=bcc)

    @mcp.tool(name='gmail.send_draft')
    async def send_draft(draft_id: str, agent: str | None = None) -> dict:
        """Send an exact snapshot of a draft after operator approval. Original draft is retained."""
        resolved, guard = resolve_agent(agent)
        if resolved is None:
            return {'ok': False, 'reason': 'Authenticated agent identity is missing, inactive, or does not match the request.'}
        return await tools.send_draft(resolved, draft_id, identity_guard=guard)

    return tools
