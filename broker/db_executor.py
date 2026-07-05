from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol

# Mirrors broker.db_broker._ROLE_RE. Not imported from there to avoid a
# circular import (db_broker imports from this module); role names dropped
# here must independently be re-validated at this sink regardless of what
# the caller already checked.
_ROLE_RE = re.compile(r"agentgate_[0-9a-f]+")


@dataclass(frozen=True)
class AdminDsn:
    host: str
    port: int
    dbname: str
    user: str
    # Suppressed from repr so a stray log/print of an AdminDsn (or a dataclass
    # containing one) never leaks the admin password in cleartext.
    password: str = field(repr=False)


# SqlStatement.sql may contain a cleartext one-time password (e.g. the minted
# CREATE ROLE ... PASSWORD '...' statement) — never log or print it.
@dataclass(frozen=True)
class SqlStatement:
    sql: str
    params: tuple = field(default_factory=tuple)


class DbExecutor(Protocol):
    async def run_admin(self, dsn: AdminDsn, statements: list[SqlStatement]) -> None: ...
    async def list_expired_roles(self, dsn: AdminDsn, pattern: str) -> list[str]: ...
    async def drop_role(self, dsn: AdminDsn, role: str) -> None: ...


class AsyncpgExecutor:
    """Real DbExecutor over asyncpg. Not exercised by unit tests (they inject a
    fake); covered by the skip-gated integration test."""

    async def _connect(self, dsn: AdminDsn):
        import asyncpg

        return await asyncpg.connect(
            host=dsn.host, port=dsn.port, database=dsn.dbname,
            user=dsn.user, password=dsn.password,
        )

    async def run_admin(self, dsn: AdminDsn, statements: list[SqlStatement]) -> None:
        conn = await self._connect(dsn)
        try:
            async with conn.transaction():
                for st in statements:
                    await conn.execute(st.sql, *st.params)
        finally:
            await conn.close()

    async def list_expired_roles(self, dsn: AdminDsn, pattern: str) -> list[str]:
        conn = await self._connect(dsn)
        try:
            rows = await conn.fetch(
                "SELECT rolname FROM pg_roles "
                "WHERE rolname LIKE $1 ESCAPE '\\' "
                "AND rolvaliduntil IS NOT NULL AND rolvaliduntil < now()",
                pattern,
            )
            return [r["rolname"] for r in rows]
        finally:
            await conn.close()

    async def drop_role(self, dsn: AdminDsn, role: str) -> None:
        # Self-guard at the SQL sink: never trust the caller. Must precede the
        # connection attempt so a bad role name never even reaches the DB.
        if not _ROLE_RE.fullmatch(role):
            raise ValueError("refusing to drop a non-conforming role name")
        conn = await self._connect(dsn)
        try:
            await conn.execute(f'DROP ROLE IF EXISTS "{role}"')
        finally:
            await conn.close()
