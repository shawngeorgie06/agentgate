"""Persistent registry for local MCP agent identities.

Bearer secrets are returned only by registration/bootstrap and are stored only as
SHA-256 hashes. Tokens are generated with 256 bits of entropy.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
import re
import secrets
import sqlite3
import stat
from pathlib import Path
from typing import Any

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{32,512}\Z")
_RESERVED_NAMES = {"operator", "system"}


class AgentRegistryError(ValueError):
    """Invalid identity data or an unsafe registry file."""


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(value: dt.datetime | None) -> str | None:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z") if value else None


class AgentRegistry:
    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            parent_info = self.path.parent.stat()
            if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid():
                raise AgentRegistryError("Agent registry directory must be owned by you.")
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
            except FileExistsError:
                fd = None
            if fd is not None:
                os.close(fd)
            info = os.lstat(self.path)
            if stat.S_ISLNK(info.st_mode):
                raise AgentRegistryError("Agent registry must not be a symbolic link.")
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise AgentRegistryError("Agent registry must be a private file owned by you.")
        except OSError:
            raise AgentRegistryError("Could not access the private agent registry.") from None
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = None
        try:
            info = os.lstat(self.path)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise AgentRegistryError("Agent registry must be a private file owned by you.")
            conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout=10000")
            return conn
        except AgentRegistryError:
            if conn is not None:
                conn.close()
            raise
        except (OSError, sqlite3.Error):
            if conn is not None:
                conn.close()
            raise AgentRegistryError("Could not open the private agent registry.") from None

    def _initialize(self) -> None:
        conn = self._connect()
        try:
            conn.execute("PRAGMA journal_mode=DELETE")
            conn.execute("""CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                revoked_at TEXT
            )""")
        except sqlite3.Error:
            raise AgentRegistryError("Could not initialize the private agent registry.") from None
        finally:
            conn.close()

    @staticmethod
    def _validate_name(name: str) -> str:
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise AgentRegistryError("Agent name must be 1–64 URL-safe letters, digits, dots, underscores, or hyphens.")
        if name.casefold() in _RESERVED_NAMES:
            raise AgentRegistryError("This agent name is reserved for trusted local actors.")
        return name

    @staticmethod
    def _validate_token(token: str) -> str:
        if not isinstance(token, str) or not _TOKEN.fullmatch(token):
            raise AgentRegistryError("Agent token must be a 32–512 character URL-safe secret.")
        return token

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode("ascii")).hexdigest()

    @staticmethod
    def _metadata(row: sqlite3.Row, now: dt.datetime | None = None) -> dict[str, Any]:
        now = now or _now()
        expires = dt.datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")) if row["expires_at"] else None
        status = "revoked" if row["revoked_at"] else ("expired" if expires and expires <= now else "active")
        return {"id": row["id"], "name": row["name"], "created_at": row["created_at"],
                "expires_at": row["expires_at"], "revoked_at": row["revoked_at"], "status": status}

    def register(self, name: str, ttl_hours: int = 720) -> dict[str, Any]:
        name = self._validate_name(name)
        if isinstance(ttl_hours, bool) or not isinstance(ttl_hours, int) or not 1 <= ttl_hours <= 8760:
            raise AgentRegistryError("ttl_hours must be an integer from 1 through 8760.")
        token = secrets.token_urlsafe(32)
        now = _now()
        expires = _iso(now + dt.timedelta(hours=ttl_hours))
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("INSERT INTO agents VALUES (?, ?, ?, ?, ?, NULL)",
                         (name, name, self._digest(token), _iso(now), expires))
            row = conn.execute("SELECT * FROM agents WHERE id=?", (name,)).fetchone()
            conn.commit()
            return {"agent": self._metadata(row, now), "token": token}
        except sqlite3.IntegrityError:
            conn.rollback()
            raise AgentRegistryError("An agent with this name or token already exists.") from None
        finally:
            conn.close()

    def import_token(self, name: str, token: str) -> dict[str, Any]:
        """Idempotently install a pre-existing private bootstrap token."""
        name, token = self._validate_name(name), self._validate_token(token)
        digest = self._digest(token)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM agents WHERE id=?", (name,)).fetchone()
            if row:
                if secrets.compare_digest(row["token_hash"], digest):
                    conn.commit()
                    return self._metadata(row)
                raise AgentRegistryError("This agent already has a different token.")
            if conn.execute("SELECT 1 FROM agents WHERE token_hash=?", (digest,)).fetchone():
                raise AgentRegistryError("This token is already assigned to another agent.")
            now = _now()
            conn.execute("INSERT INTO agents VALUES (?, ?, ?, ?, ?, NULL)",
                         (name, name, digest, _iso(now), None))
            row = conn.execute("SELECT * FROM agents WHERE id=?", (name,)).fetchone()
            conn.commit()
            return self._metadata(row, now)
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def list_agents(self) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT * FROM agents ORDER BY created_at, id").fetchall()
            now = _now()
            return [self._metadata(row, now) for row in rows]
        finally:
            conn.close()

    def revoke(self, agent_id: str) -> bool:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute("UPDATE agents SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
                               (_iso(_now()), agent_id))
            conn.commit()
            return cur.rowcount > 0 or conn.execute("SELECT 1 FROM agents WHERE id=?", (agent_id,)).fetchone() is not None
        finally:
            conn.close()

    def authenticate(self, token: str) -> dict[str, Any] | None:
        if not isinstance(token, str) or not _TOKEN.fullmatch(token):
            return None
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM agents WHERE token_hash=?", (self._digest(token),)).fetchone()
            if row is None:
                return None
            metadata = self._metadata(row)
            return metadata if metadata["status"] == "active" else None
        finally:
            conn.close()
