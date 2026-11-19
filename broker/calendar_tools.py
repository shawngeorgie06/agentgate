"""Trusted identity, policy, and approval boundary for Google Calendar MCP tools."""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import threading
from typing import TYPE_CHECKING

from fastmcp import FastMCP

from broker.access import AccessController, AccessError
from broker.integrations.calendar import (
    INTERNAL_PREFIX, Calendar, CalendarError, event_body, event_id_for, validate_calendar_id,
)

if TYPE_CHECKING:
    from broker.mcp_server import Broker


_REQUEST_ID = re.compile(r'^[A-Za-z0-9_-]{16,128}$')
_UNCERTAIN = ' The result may be uncertain; check Google Calendar before retrying.'


class CalendarTools:
    def __init__(self, broker: Broker, calendar: Calendar):
        self.broker = broker
        self.calendar = calendar
        self.access = AccessController(broker)
        self._attempt_lock = threading.RLock()
        self._ledger_name = INTERNAL_PREFIX + 'calendar-attempts'
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
        return await self.access.execute(self.calendar, agent, resource, operation,
                                         identity_guard=identity_guard, **arguments)

    async def create_event(self, agent: str, *, summary: str, start: str, end: str,
                           time_zone: str = '', location: str = '', description: str = '',
                           calendar_id: str = 'primary', request_id: str, identity_guard=None) -> dict:
        if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
            return {'ok': False, 'reason': 'request_id must contain 16 to 128 URL-safe letters, numbers, underscores, or hyphens.'}
        # Only a hash of the agent and request ID is persisted. A stable caller
        # request ID makes duplicate submissions safe across reconnects and restarts.
        attempt_key = hashlib.sha256(f'{agent}\0{request_id}'.encode('utf-8')).hexdigest()
        with self._attempt_lock:
            if attempt_key in self._attempts:
                return {'ok': False, 'reason': 'This event request already has an attempt. Check Google Calendar before retrying.'}
        try:
            calendar_id = validate_calendar_id(calendar_id)
            body = event_body(summary=summary, start=start, end=end, time_zone=time_zone,
                              location=location, description=description)
        except CalendarError as exc:
            return {'ok': False, 'reason': str(exc)}
        # The operator approves exactly this calendar and body; nothing is refetched later.
        frozen = json.loads(json.dumps({'calendar_id': calendar_id, 'event': body}))
        details = json.dumps(frozen, ensure_ascii=True, indent=2, sort_keys=True)
        guard = self.access.access_guard(agent, 'calendar:write', identity_guard)
        if not await self.access.authorize(agent, 'calendar:write', details, guard, require_approval=True):
            return {'ok': False, 'reason': 'Event creation denied or approval timed out.'}

        dispatch_started = False

        def before_dispatch():
            nonlocal dispatch_started
            if not guard():
                raise AccessError('Agent access is no longer active, or permissions changed or expired.')
            # Persist immediately before the single POST. If the transport outcome
            # is uncertain, the marker stays so caller retries cannot duplicate it.
            with self._attempt_lock:
                if attempt_key in self._attempts:
                    raise CalendarError('This event request already has an attempt. Check Google Calendar before retrying.')
                self._attempts.add(attempt_key)
                self.broker.store.store(self._ledger_name, json.dumps(sorted(self._attempts)))
                dispatch_started = True

        try:
            data = await asyncio.to_thread(
                self.calendar.call, 'create_event', before_dispatch=before_dispatch,
                calendar_id=frozen['calendar_id'], event_id=event_id_for(agent, request_id), body=frozen['event'],
            )
        except AccessError:
            self._audit(agent, 'calendar:write', 'create_event', 'denied')
            return {'ok': False, 'reason': 'Agent access is no longer active, or permissions changed or expired.'}
        except CalendarError as exc:
            self._audit(agent, 'calendar:write', 'create_event', 'failed')
            return {'ok': False, 'reason': str(exc) + (_UNCERTAIN if dispatch_started else '')}
        except Exception:
            self._audit(agent, 'calendar:write', 'create_event', 'failed')
            return {'ok': False, 'reason': 'Google Calendar event creation failed.' + (_UNCERTAIN if dispatch_started else '')}
        self._audit(agent, 'calendar:write', 'create_event', 'completed')
        return {'ok': True, 'data': data}


def register_calendar_tools(mcp: FastMCP, broker: Broker, calendar: Calendar | None = None, *,
                            tools: CalendarTools | None = None, identity_resolver=None,
                            trusted_agent: str | None = None) -> CalendarTools:
    tools = tools or CalendarTools(broker, calendar or Calendar(broker.store))
    if identity_resolver is None and trusted_agent is None:
        raise ValueError('Calendar tools require a trusted identity resolver.')

    def resolve_agent(supplied: str | None):
        if identity_resolver is not None:
            return identity_resolver(supplied)
        if supplied is not None and supplied != trusted_agent:
            return None, None
        return trusted_agent, lambda: True

    def missing_identity():
        return {'ok': False, 'reason': 'Authenticated agent identity is missing, inactive, or does not match the request.'}

    @mcp.tool(name='calendar.calendars')
    async def calendars(limit: int = 50, page_token: str | None = None, agent: str | None = None) -> dict:
        """List the calendars the connected Google account can see."""
        resolved, guard = resolve_agent(agent)
        if resolved is None:
            return missing_identity()
        return await tools.execute(resolved, 'calendar:read', 'calendars', identity_guard=guard,
                                   limit=limit, page_token=page_token)

    @mcp.tool(name='calendar.events')
    async def events(time_min: str, time_max: str, calendar_id: str = 'primary', query: str = '',
                     limit: int = 25, page_token: str | None = None, agent: str | None = None) -> dict:
        """List events between two RFC 3339 times with offsets, expanded and ordered by start (range up to 366 days)."""
        resolved, guard = resolve_agent(agent)
        if resolved is None:
            return missing_identity()
        return await tools.execute(resolved, 'calendar:read', 'events', identity_guard=guard,
                                   time_min=time_min, time_max=time_max, calendar_id=calendar_id,
                                   query=query, limit=limit, page_token=page_token)

    @mcp.tool(name='calendar.freebusy')
    async def freebusy(time_min: str, time_max: str, calendar_ids: list[str] | None = None,
                       agent: str | None = None) -> dict:
        """Return busy intervals between two RFC 3339 times (range up to 62 days); defaults to the primary calendar."""
        resolved, guard = resolve_agent(agent)
        if resolved is None:
            return missing_identity()
        return await tools.execute(resolved, 'calendar:read', 'freebusy', identity_guard=guard,
                                   time_min=time_min, time_max=time_max, calendar_ids=calendar_ids)

    @mcp.tool(name='calendar.create_event')
    async def create_event(summary: str, start: str, end: str, request_id: str = '', time_zone: str = '',
                           location: str = '', description: str = '', calendar_id: str = 'primary',
                           agent: str | None = None) -> dict:
        """Create one event after explicit operator approval. Use RFC 3339 times with offsets, or YYYY-MM-DD dates
        for an all-day event (end date exclusive). No attendees are invited. Reuse request_id for retries."""
        resolved, guard = resolve_agent(agent)
        if resolved is None:
            return missing_identity()
        return await tools.create_event(resolved, summary=summary, start=start, end=end, time_zone=time_zone,
                                        location=location, description=description, calendar_id=calendar_id,
                                        request_id=request_id, identity_guard=guard)

    return tools
