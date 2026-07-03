from __future__ import annotations

import datetime
import re

import pytest

from broker import db_broker
from broker.db_executor import AdminDsn, SqlStatement
from broker.db_resource_store import DbResource


def _res():
    return DbResource(
        name="analytics-ro", host="db.internal", port=5432, dbname="analytics",
        admin_user="agentgate_admin", admin_password="admin-pw",
        grants=[{"verb": "SELECT", "objects": ["public.events"]}],
        created_at="2026-07-02T10:00:00+00:00",
    )


class FakeExecutor:
    def __init__(self, expired=None, drop_raises=()):
        self.run_admin_calls = []
        self.dropped = []
        self._expired = list(expired or [])
        self._drop_raises = set(drop_raises)

    async def run_admin(self, dsn, statements):
        self.run_admin_calls.append((dsn, statements))

    async def list_expired_roles(self, dsn, pattern):
        return list(self._expired)

    async def drop_role(self, dsn, role):
        if role in self._drop_raises:
            raise RuntimeError("session still attached")
        self.dropped.append(role)


def test_generated_role_and_password_match_safe_charsets():
    assert re.match(r"^agentgate_[0-9a-f]+$", db_broker.generate_role_name())
    assert re.match(r"^[A-Za-z0-9_-]+$", db_broker.generate_password())


def test_build_mint_statements_shape():
    stmts = db_broker.build_mint_statements(
        "agentgate_ab12", "PW-safe_123", _res(), "2026-07-02T10:15:00+00:00")
    assert stmts[0] == SqlStatement(
        "CREATE ROLE \"agentgate_ab12\" LOGIN PASSWORD 'PW-safe_123' "
        "VALID UNTIL '2026-07-02T10:15:00+00:00'")
    assert stmts[1] == SqlStatement('GRANT SELECT ON "public"."events" TO "agentgate_ab12"')


def test_build_mint_statements_rejects_unsafe_generated_values():
    with pytest.raises(AssertionError):
        db_broker.build_mint_statements("not_prefixed", "pw", _res(), "2026-07-02T10:15:00+00:00")
    with pytest.raises(AssertionError):
        db_broker.build_mint_statements("agentgate_ab12", "pw'; DROP", _res(), "2026-07-02T10:15:00+00:00")


async def test_mint_runs_statements_and_returns_cred():
    ex = FakeExecutor()
    cred = await db_broker.mint(ex, _res(), ttl_minutes=15)
    assert len(ex.run_admin_calls) == 1
    dsn, statements = ex.run_admin_calls[0]
    assert dsn == AdminDsn("db.internal", 5432, "analytics", "agentgate_admin", "admin-pw")
    assert statements[0].sql.startswith('CREATE ROLE "agentgate_')
    assert cred.username.startswith("agentgate_")
    assert cred.host == "db.internal" and cred.port == 5432 and cred.dbname == "analytics"
    # expires_at is a future UTC ISO timestamp.
    exp = datetime.datetime.fromisoformat(cred.expires_at)
    assert exp.tzinfo is not None and exp > datetime.datetime.now(datetime.timezone.utc)


async def test_reap_drops_only_agentgate_expired_roles():
    ex = FakeExecutor(expired=["agentgate_dead1", "some_other_role", "agentgate_dead2"])
    dropped = await db_broker.reap(ex, _res())
    assert dropped == ["agentgate_dead1", "agentgate_dead2"]  # non-namespaced skipped
    assert "some_other_role" not in ex.dropped


async def test_reap_skips_role_whose_drop_fails_and_continues():
    ex = FakeExecutor(expired=["agentgate_a", "agentgate_b"], drop_raises={"agentgate_a"})
    dropped = await db_broker.reap(ex, _res())
    assert dropped == ["agentgate_b"]  # a failed, b still dropped
