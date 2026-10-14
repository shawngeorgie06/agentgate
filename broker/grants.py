"""Private, persistent leases that temporarily override agent permissions."""
from __future__ import annotations

import datetime as dt
import secrets
import sqlite3
from typing import Any, Callable


class GrantError(ValueError):
    """A requested temporary access lease is invalid or conflicts with a live lease."""


_PERMISSIONS = {
    "gmail:read": {"allow", "ask"},
    "gmail:draft": {"allow", "ask"},
    "gmail:send": {"ask"},
    "github:read": {"allow", "ask"},
    "github:write": {"ask"},
}


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _stamp(value: dt.datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


class TemporaryGrants:
    """Lease metadata in the same permission-restricted SQLite file as identities."""

    def __init__(self, registry, clock: Callable[[], dt.datetime] | None = None):
        self.registry = registry
        self.clock = clock or _utc_now
        conn = registry._connect()
        try:
            conn.execute("""CREATE TABLE IF NOT EXISTS temporary_grants (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                resource TEXT NOT NULL,
                permission TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                reason TEXT NOT NULL,
                revoked_at TEXT
            )""")
            conn.execute("CREATE INDEX IF NOT EXISTS grants_agent_resource ON temporary_grants(agent_id, resource)")
        except sqlite3.Error:
            raise GrantError("Could not initialize the private temporary access store.") from None
        finally:
            conn.close()

    def _agent_active(self, agent_id: str) -> bool:
        return any(agent["id"] == agent_id and agent["status"] == "active"
                   for agent in self.registry.list_agents())

    @staticmethod
    def _row_data(row, status: str) -> dict[str, Any]:
        return {"id": row["id"], "agent_id": row["agent_id"], "resource": row["resource"],
                "permission": row["permission"], "created_at": row["created_at"],
                "expires_at": row["expires_at"], "revoked_at": row["revoked_at"],
                "reason": row["reason"], "status": status}

    def _status(self, row, now: dt.datetime) -> str:
        if row["revoked_at"]:
            return "revoked"
        if _parse(row["expires_at"]) <= now:
            return "expired"
        if not self._agent_active(row["agent_id"]):
            return "inactive"
        return "active"

    def create(self, agent_id: str, resource: str, permission: str, minutes: int, reason: str = "") -> dict[str, Any]:
        if not isinstance(agent_id, str) or not agent_id or not self._agent_active(agent_id):
            raise GrantError("Temporary grants require an active enrolled agent.")
        if (not isinstance(resource, str) or not isinstance(permission, str)
                or resource not in _PERMISSIONS or permission not in _PERMISSIONS.get(resource, set())):
            raise GrantError("Permission is not allowed for this resource.")
        if isinstance(minutes, bool) or not isinstance(minutes, int) or not 1 <= minutes <= 1440:
            raise GrantError("minutes must be an integer from 1 through 1440.")
        if not isinstance(reason, str) or len(reason) > 500:
            raise GrantError("reason must be a string of at most 500 characters.")
        now = self.clock()
        created, expires = _stamp(now), _stamp(now + dt.timedelta(minutes=minutes))
        grant_id = secrets.token_urlsafe(24)
        conn = self.registry._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            # Recheck identity within the transaction to avoid a stale preflight.
            agent = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
            if agent is None or self.registry._metadata(agent, now)["status"] != "active":
                raise GrantError("Temporary grants require an active enrolled agent.")
            old = conn.execute("SELECT * FROM temporary_grants WHERE agent_id=? AND resource=? AND revoked_at IS NULL",
                               (agent_id, resource)).fetchall()
            if any(_parse(row["expires_at"]) > now for row in old):
                raise GrantError("An active grant already exists for this agent and resource.")
            conn.execute("INSERT INTO temporary_grants VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
                         (grant_id, agent_id, resource, permission, created, expires, reason))
            row = conn.execute("SELECT * FROM temporary_grants WHERE id=?", (grant_id,)).fetchone()
            conn.commit()
            return self._row_data(row, "active")
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def list_grants(self) -> list[dict[str, Any]]:
        conn = self.registry._connect()
        try:
            rows = conn.execute("SELECT * FROM temporary_grants ORDER BY created_at, rowid").fetchall()
            now = self.clock()
            return [self._row_data(row, self._status(row, now)) for row in rows]
        finally:
            conn.close()

    def active_grant(self, agent_id: str, resource: str) -> dict[str, Any] | None:
        if not self._agent_active(agent_id):
            return None
        conn = self.registry._connect()
        try:
            rows = conn.execute("""SELECT * FROM temporary_grants
                                  WHERE agent_id=? AND resource=? AND revoked_at IS NULL
                                  ORDER BY created_at DESC, id DESC""", (agent_id, resource)).fetchall()
            now = self.clock()
            for row in rows:
                if _parse(row["expires_at"]) > now:
                    return self._row_data(row, "active")
            return None
        finally:
            conn.close()

    def revoke(self, grant_id: str) -> bool:
        conn = self.registry._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute("UPDATE temporary_grants SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
                               (_stamp(self.clock()), grant_id))
            conn.commit()
            return cur.rowcount > 0 or conn.execute("SELECT 1 FROM temporary_grants WHERE id=?", (grant_id,)).fetchone() is not None
        finally:
            conn.close()
