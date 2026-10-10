"""Policy and approval boundaries for Gmail MCP tools."""
from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING

from fastmcp import FastMCP

from broker import state
from broker.integrations.gmail import Gmail, GmailError, INTERNAL_PREFIX

if TYPE_CHECKING:
    from broker.mcp_server import Broker


class GmailTools:
    def __init__(self, broker: Broker, gmail: Gmail):
        self.broker = broker
        self.gmail = gmail
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

    async def authorize(self, agent: str, resource: str, details: str | None = None) -> bool:
        self.broker.total_requests += 1
        mode = state.read_mode(self.broker.config.state_path)
        decision = self.broker.engine.evaluate(agent, resource)
        policy = decision.policy_name
        sending = resource == 'gmail:send'
        if not sending and mode == 'auto' and decision.auto_approve:
            self.audit(agent, resource, policy, mode, 'approved')
            return True
        if not decision.auto_approve and not decision.escalate:
            self.audit(agent, resource, policy, mode, 'denied')
            return False
        self.broker.escalated_requests += 1
        self.audit(agent, resource, policy, mode, 'escalated')
        try:
            approved = await self.broker.approvals.submit(
                agent, resource,
                timeout=self.broker.config.escalation_timeout_seconds or None,
                details=details,
            )
        except asyncio.TimeoutError:
            self.audit(agent, resource, policy, mode, 'expired')
            return False
        self.audit(agent, resource, policy, mode, 'approved' if approved else 'denied')
        return approved

    async def execute(self, agent: str, resource: str, operation: str, **arguments) -> dict:
        if not await self.authorize(agent, resource):
            return {'ok': False, 'reason': 'Access denied or approval timed out.'}
        try:
            data = await asyncio.to_thread(self.gmail.call, operation, **arguments)
        except GmailError as exc:
            self.audit(agent, resource, operation, state.read_mode(self.broker.config.state_path), 'failed')
            return {'ok': False, 'reason': str(exc)}
        self.audit(agent, resource, operation, state.read_mode(self.broker.config.state_path), 'completed')
        return {'ok': True, 'data': data}

    async def send_draft(self, agent: str, draft_id: str) -> dict:
        async with self._send_lock:
            if draft_id in self._sent_drafts:
                return {'ok': False, 'reason': 'This draft already has a send attempt. Check Gmail before creating another draft.'}
            # Access to draft contents must itself be authorized.
            if not await self.authorize(agent, 'gmail:draft'):
                return {'ok': False, 'reason': 'Draft access denied or approval timed out.'}
            try:
                snapshot = await asyncio.to_thread(self.gmail.call, 'snapshot', draft_id=draft_id)
            except GmailError as exc:
                return {'ok': False, 'reason': str(exc)}
            details = json.dumps({'draft_id': draft_id, **snapshot['preview']}, ensure_ascii=True, indent=2)
            if not await self.authorize(agent, 'gmail:send', details=details):
                return {'ok': False, 'reason': 'Send denied or approval timed out.'}
            # Mark before dispatch: network failures can leave delivery uncertain.
            # Never retry a non-idempotent send automatically.
            self._sent_drafts.add(draft_id)
            self.broker.store.store(self._ledger_name, json.dumps(sorted(self._sent_drafts)))
            try:
                data = await asyncio.to_thread(self.gmail.call, 'send', snapshot=snapshot)
            except GmailError as exc:
                self.audit(agent, 'gmail:send', 'send', state.read_mode(self.broker.config.state_path), 'failed')
                return {'ok': False, 'reason': str(exc) + ' Delivery may be uncertain; check Gmail before retrying.'}
            self.audit(agent, 'gmail:send', 'send', state.read_mode(self.broker.config.state_path), 'completed')
            return {'ok': True, 'data': data, 'draft_retained': True}


def register_gmail_tools(mcp: FastMCP, broker: Broker, gmail: Gmail | None = None) -> GmailTools:
    tools = GmailTools(broker, gmail or Gmail(broker.store))

    @mcp.tool(name='gmail.search')
    async def search(agent: str, query: str, limit: int = 20, page_token: str | None = None) -> dict:
        """Search Gmail using its query syntax. Returns message IDs and pagination."""
        return await tools.execute(agent, 'gmail:read', 'search', query=query, limit=limit, page_token=page_token)

    @mcp.tool(name='gmail.read')
    async def read(agent: str, message_id: str) -> dict:
        """Read email headers and body; attachment contents are not downloaded."""
        return await tools.execute(agent, 'gmail:read', 'read', message_id=message_id)

    @mcp.tool(name='gmail.draft')
    async def draft(agent: str, to: str, subject: str, body: str, cc: str = '', bcc: str = '') -> dict:
        """Create a plain-text Gmail draft. This does not send email."""
        return await tools.execute(agent, 'gmail:draft', 'draft', to=to, subject=subject, body=body, cc=cc, bcc=bcc)

    @mcp.tool(name='gmail.send_draft')
    async def send_draft(agent: str, draft_id: str) -> dict:
        """Send an exact snapshot of a draft after operator approval. Original draft is retained."""
        return await tools.send_draft(agent, draft_id)

    return tools
