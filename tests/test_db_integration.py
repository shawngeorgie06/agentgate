# tests/test_db_integration.py
from __future__ import annotations

import asyncio
import os

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("AGENTGATE_TEST_PG_DSN"),
    reason="set AGENTGATE_TEST_PG_DSN=postg://user:pw@host:port/db (superuser or CREATEROLE) to run",
)


def _dsn_parts():
    # AGENTGATE_TEST_PG_DSN=postgresql://user:pw@host:port/dbname
    from urllib.parse import urlparse
    u = urlparse(os.environ["AGENTGATE_TEST_PG_DSN"])
    return dict(host=u.hostname, port=u.port or 5432, dbname=u.path.lstrip("/"),
                user=u.username, password=u.password)


async def test_mint_grant_and_reap_against_real_postgres(tmp_path):
    import asyncpg

    from broker import db_broker
    from broker.db_executor import AsyncpgExecutor
    from broker.db_resource_store import DbResource

    parts = _dsn_parts()
    # Prepare a table the ephemeral role may read.
    admin = await asyncpg.connect(**parts)
    await admin.execute("CREATE TABLE IF NOT EXISTS ag_itest (id int)")
    await admin.execute("INSERT INTO ag_itest VALUES (1)")
    await admin.close()

    resource = DbResource(
        name="itest", host=parts["host"], port=parts["port"], dbname=parts["dbname"],
        admin_user=parts["user"], admin_password=parts["password"],
        grants=[{"verb": "SELECT", "objects": ["ag_itest"]}],
        created_at="2026-07-02T10:00:00+00:00",
    )
    ex = AsyncpgExecutor()

    cred = await db_broker.mint(ex, resource, ttl_minutes=1)

    # The ephemeral role can SELECT the granted table...
    conn = await asyncpg.connect(host=cred.host, port=cred.port, database=cred.dbname,
                                 user=cred.username, password=cred.password)
    try:
        assert await conn.fetchval("SELECT count(*) FROM ag_itest") == 1
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute("INSERT INTO ag_itest VALUES (2)")  # not granted
    finally:
        await conn.close()

    # Expire the role and reap it.
    admin = await asyncpg.connect(**parts)
    await admin.execute(f'ALTER ROLE "{cred.username}" VALID UNTIL \'2000-01-01\'')
    await admin.close()
    dropped = await db_broker.reap(ex, resource)
    assert cred.username in dropped

    # Cleanup the test table.
    admin = await asyncpg.connect(**parts)
    await admin.execute("DROP TABLE ag_itest")
    await admin.close()
