from __future__ import annotations

import datetime
import re
import secrets

from dataclasses import dataclass

from broker import db_grants
from broker.db_executor import AdminDsn, DbExecutor, SqlStatement
from broker.db_resource_store import DbResource

ROLE_PREFIX = "agentgate_"
_ROLE_RE = re.compile(r"^agentgate_[0-9a-f]+$")
_PW_RE = re.compile(r"^[A-Za-z0-9_-]+$")
# LIKE pattern for the reaper; underscore escaped so it is literal.
_EXPIRED_PATTERN = r"agentgate\_%"


@dataclass(frozen=True)
class MintedCred:
    host: str
    port: int
    dbname: str
    username: str
    password: str
    expires_at: str


def generate_role_name() -> str:
    return ROLE_PREFIX + secrets.token_hex(8)


def generate_password() -> str:
    return secrets.token_urlsafe(24)


def admin_dsn(resource: DbResource) -> AdminDsn:
    return AdminDsn(
        host=resource.host, port=resource.port, dbname=resource.dbname,
        user=resource.admin_user, password=resource.admin_password,
    )


def build_mint_statements(
    role: str, password: str, resource: DbResource, expires_at: str
) -> list[SqlStatement]:
    # Postgres DDL takes no bind parameters, so these values are placed into SQL
    # text directly. They are ALL broker-generated; asserting the safe charsets
    # guarantees no quote/backslash can appear, so the literal/identifier
    # quoting below cannot be broken out of. No agent-supplied value is used.
    if not _ROLE_RE.fullmatch(role):
        raise ValueError("refusing to build DDL for a non-conforming role name")
    if not _PW_RE.fullmatch(password):
        raise ValueError("refusing to build DDL for a non-conforming password")
    create = SqlStatement(
        f'CREATE ROLE "{role}" LOGIN PASSWORD \'{password}\' VALID UNTIL \'{expires_at}\''
    )
    grants = [SqlStatement(sql) for sql in db_grants.build_grant_statements(role, resource.grants)]
    return [create, *grants]


async def mint(executor: DbExecutor, resource: DbResource, ttl_minutes: int) -> MintedCred:
    role = generate_role_name()
    password = generate_password()
    expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=ttl_minutes)
    expires_at = expires.isoformat(timespec="seconds")
    statements = build_mint_statements(role, password, resource, expires_at)
    await executor.run_admin(admin_dsn(resource), statements)
    return MintedCred(
        host=resource.host, port=resource.port, dbname=resource.dbname,
        username=role, password=password, expires_at=expires_at,
    )


async def reap(executor: DbExecutor, resource: DbResource) -> list[str]:
    dsn = admin_dsn(resource)
    expired = await executor.list_expired_roles(dsn, _EXPIRED_PATTERN)
    dropped: list[str] = []
    for role in expired:
        if not _ROLE_RE.match(role):
            continue  # never touch anything outside our namespace
        try:
            await executor.drop_role(dsn, role)
        except Exception:
            continue  # session still attached; retry next sweep
        dropped.append(role)
    return dropped
