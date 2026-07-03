from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class AdminDsn:
    host: str
    port: int
    dbname: str
    user: str
    password: str


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
        conn = await self._connect(dsn)
        try:
            await conn.execute(f'DROP ROLE IF EXISTS "{role}"')
        finally:
            await conn.close()
