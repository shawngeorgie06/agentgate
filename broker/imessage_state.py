"""Replay-safe ledger for the iMessage agent bridge.

The ledger lives in the same private SQLite file as the agent registry. Raw chat,
message, and database identifiers never reach that file: each is stored as an
HMAC-SHA256 digest under a random key kept in a separate private 0600 file.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import os
import secrets
import sqlite3
import stat
from pathlib import Path
from typing import Any

from broker.agent_registry import AgentRegistry, AgentRegistryError

_KEY_BYTES = 32
_KEY_FILE = "imessage-ledger.key"
_RESULT_STATUSES = frozenset({"sent", "failed", "skipped"})


class MessageLedgerError(ValueError):
    """Invalid ledger input or an unavailable private ledger store."""


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(value: dt.datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _aware(value: Any) -> bool:
    return isinstance(value, dt.datetime) and value.utcoffset() is not None


def _text(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 4096


def _same(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _load_or_create_key(path: Path) -> bytes:
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        fd = None
    try:
        if fd is not None:
            try:
                key = secrets.token_bytes(_KEY_BYTES)
                if os.write(fd, key) != _KEY_BYTES:
                    raise OSError("short write")
                os.fsync(fd)
            except OSError:
                os.close(fd)
                fd = None
                os.unlink(path)
                raise
            os.close(fd)
            fd = None
            return key
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise MessageLedgerError("iMessage ledger key must be a private file owned by you.")
        key = os.read(fd, _KEY_BYTES + 1)
        if len(key) != _KEY_BYTES:
            raise MessageLedgerError("iMessage ledger key is malformed.")
        return key
    except MessageLedgerError:
        raise
    except OSError:
        raise MessageLedgerError("Could not access the iMessage ledger key.") from None
    finally:
        if fd is not None:
            os.close(fd)


class MessageLedger:
    def __init__(self, registry: AgentRegistry):
        self._registry = registry
        self._key = _load_or_create_key(Path(registry.path).parent / _KEY_FILE)
        conn = self._connect()
        try:
            conn.execute("""CREATE TABLE IF NOT EXISTS imessage_baselines (
                chat_key TEXT PRIMARY KEY,
                database_key TEXT NOT NULL,
                revision TEXT NOT NULL,
                baseline_at TEXT NOT NULL,
                tail_rowid INTEGER NOT NULL
            )""")
            conn.execute("""CREATE TABLE IF NOT EXISTS imessage_claims (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_key TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                claimed_at TEXT NOT NULL,
                attempted_at TEXT,
                finished_at TEXT
            )""")
        except sqlite3.Error:
            raise MessageLedgerError("Could not initialize the iMessage ledger.") from None
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        try:
            conn = self._registry._connect()
        except AgentRegistryError:
            raise MessageLedgerError("Could not open the private agent registry.") from None
        try:
            conn.execute("PRAGMA secure_delete=ON")
        except sqlite3.Error:
            conn.close()
            raise MessageLedgerError("Could not open the iMessage ledger.") from None
        return conn

    def _digest(self, domain: str, value: str) -> str:
        message = domain.encode("ascii") + b"\0" + value.encode("utf-8")
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def baseline(self, chat_id: str, database_id: str, now: dt.datetime, tail_rowid: int = 0) -> dict[str, Any]:
        """Start (or replace) the capture baseline for a chat without touching claim history."""
        if not _text(chat_id) or not _text(database_id):
            raise MessageLedgerError("Chat and database identifiers are required.")
        if not _aware(now):
            raise MessageLedgerError("Baseline time must be timezone-aware.")
        if isinstance(tail_rowid, bool) or not isinstance(tail_rowid, int) or tail_rowid < 0:
            raise MessageLedgerError("tail_rowid must be a non-negative integer.")
        revision = secrets.token_urlsafe(16)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """INSERT INTO imessage_baselines (chat_key, database_key, revision, baseline_at, tail_rowid)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(chat_key) DO UPDATE SET
                       database_key=excluded.database_key,
                       revision=excluded.revision,
                       baseline_at=excluded.baseline_at,
                       tail_rowid=excluded.tail_rowid""",
                (self._digest("chat", chat_id), self._digest("database", database_id),
                 revision, now.isoformat(), tail_rowid),
            )
            conn.commit()
        except sqlite3.Error:
            if conn.in_transaction:
                conn.rollback()
            raise MessageLedgerError("Could not record the iMessage baseline.") from None
        finally:
            conn.close()
        return {"revision": revision, "baseline_at": now.isoformat(), "tail_rowid": tail_rowid}

    def is_database_current(self, chat_id: str, database_id: str) -> bool:
        if not _text(chat_id) or not _text(database_id):
            return False
        conn = self._connect()
        try:
            row = conn.execute("SELECT database_key FROM imessage_baselines WHERE chat_key=?",
                               (self._digest("chat", chat_id),)).fetchone()
            return row is not None and _same(row["database_key"], self._digest("database", database_id))
        except sqlite3.Error:
            raise MessageLedgerError("Could not read the iMessage baseline.") from None
        finally:
            conn.close()

    def claim(self, chat_id: str, message_id: str, date: dt.datetime, rowid: int, *,
              revision: str | None = None, database_id: str | None = None) -> bool:
        """Return True exactly once per message id when the message is eligible for a reply.

        Invalid or ineligible input returns False. Storage failures raise MessageLedgerError.
        """
        if not _text(chat_id) or not _text(message_id) or not _aware(date):
            return False
        if isinstance(rowid, bool) or not isinstance(rowid, int):
            return False
        if revision is not None and not isinstance(revision, str):
            return False
        if database_id is not None and not _text(database_id):
            return False
        chat_key = self._digest("chat", chat_id)
        message_key = self._digest("message", message_id)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            base = conn.execute("SELECT * FROM imessage_baselines WHERE chat_key=?", (chat_key,)).fetchone()
            eligible = (
                base is not None
                and date > dt.datetime.fromisoformat(base["baseline_at"])
                and rowid > base["tail_rowid"]
                and (revision is None or _same(revision, base["revision"]))
                and (database_id is None or _same(self._digest("database", database_id), base["database_key"]))
            )
            if not eligible:
                conn.rollback()
                return False
            conn.execute("INSERT INTO imessage_claims (message_key, status, claimed_at) VALUES (?, 'claimed', ?)",
                         (message_key, _iso(_now())))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Already claimed: the UNIQUE message_key constraint is the dedupe guarantee.
            conn.rollback()
            return False
        except (ValueError, TypeError):
            # Corrupt baseline row: fail closed.
            if conn.in_transaction:
                conn.rollback()
            return False
        except sqlite3.Error:
            if conn.in_transaction:
                conn.rollback()
            raise MessageLedgerError("Could not record the iMessage claim.") from None
        finally:
            conn.close()

    def mark_attempted(self, message_id: str) -> bool:
        if not _text(message_id):
            raise MessageLedgerError("Message identifier is required.")
        conn = self._connect()
        try:
            cur = conn.execute("UPDATE imessage_claims SET status='attempted', attempted_at=? "
                               "WHERE message_key=? AND status='claimed'",
                               (_iso(_now()), self._digest("message", message_id)))
            return cur.rowcount > 0
        except sqlite3.Error:
            raise MessageLedgerError("Could not update the iMessage claim.") from None
        finally:
            conn.close()

    def mark_result(self, message_id: str, status: str) -> bool:
        if not _text(message_id):
            raise MessageLedgerError("Message identifier is required.")
        if status not in _RESULT_STATUSES:
            raise MessageLedgerError("Unsupported result status.")
        conn = self._connect()
        try:
            cur = conn.execute("UPDATE imessage_claims SET status=?, finished_at=? "
                               "WHERE message_key=? AND status NOT IN ('sent', 'failed', 'skipped')",
                               (status, _iso(_now()), self._digest("message", message_id)))
            return cur.rowcount > 0
        except sqlite3.Error:
            raise MessageLedgerError("Could not update the iMessage claim.") from None
        finally:
            conn.close()

    def list_recent(self, limit: int = 20) -> list[dict[str, Any]]:
        """Newest-first status summaries. Never includes chat, message, or database identifiers."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise MessageLedgerError("limit must be an integer from 1 through 100.")
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT status, claimed_at, attempted_at, finished_at FROM imessage_claims "
                "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [{"status": row["status"], "claimed_at": row["claimed_at"],
                     "attempted_at": row["attempted_at"], "finished_at": row["finished_at"]} for row in rows]
        except sqlite3.Error:
            raise MessageLedgerError("Could not read the iMessage ledger.") from None
        finally:
            conn.close()
