"""Operator API helpers for temporary access leases.

Dashboard route code owns authentication, HTTP status mapping, and request-size
limits. These functions only validate the operation and call the private store.
"""
from __future__ import annotations

from typing import Any

from broker.grants import GrantError


def get_grants(broker) -> dict[str, Any]:
    grants = getattr(broker, "temporary_grants", None)
    registry = getattr(broker, "agent_registry", None)
    if grants is None or registry is None:
        return {"available": False, "agents": [], "grants": []}
    return {"available": True, "agents": registry.list_agents(), "grants": grants.list_grants()}


def create_grant(broker, payload: dict[str, Any]) -> dict[str, Any]:
    grants = getattr(broker, "temporary_grants", None)
    if grants is None:
        raise GrantError("Temporary access management is unavailable.")
    if not isinstance(payload, dict):
        raise GrantError("Invalid grant request.")
    result = grants.create(payload.get("agent_id"), payload.get("resource"),
                           payload.get("permission"), payload.get("minutes"),
                           payload.get("reason", ""))
    invalidate = getattr(broker, "invalidate_agent_requests", None)
    if invalidate:
        invalidate()
    return {"grant": result, "grants": grants.list_grants()}


def revoke_grant(broker, payload: dict[str, Any]) -> dict[str, Any]:
    grants = getattr(broker, "temporary_grants", None)
    if grants is None:
        raise GrantError("Temporary access management is unavailable.")
    if not isinstance(payload, dict) or not isinstance(payload.get("grant_id"), str):
        raise GrantError("Invalid grant request.")
    grant_id = payload["grant_id"]
    before = next((row for row in grants.list_grants() if row["id"] == grant_id), None)
    found = grants.revoke(grant_id)
    if not found:
        raise GrantError("This grant no longer exists. Reload and review the current grants.")
    if before and before["status"] == "active":
        invalidate = getattr(broker, "invalidate_agent_requests", None)
        if invalidate:
            invalidate()
    return {"revoked": True, "grants": grants.list_grants()}
