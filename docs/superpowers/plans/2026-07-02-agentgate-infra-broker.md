# AgentGate Infra Broker (PostgreSQL) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an authenticated agent request a named PostgreSQL resource over MCP and receive a fresh, scoped, short-lived login role (auto-reaped after its TTL) — never a standing DB credential.

**Architecture:** Reuse the existing AgentGate spine unchanged (agent-key auth, policy engine, escalation queue + flood cap, audit log, HTTP MCP server, `EncryptedStore`). Add: an encrypted `DbResourceStore` of operator-registered resources (DSN + admin creds + grants), a pure grant-validation/SQL-building module, an injectable `DbExecutor` seam (real `asyncpg` impl + fake for network-free tests), a `db_broker` that mints/reaps ephemeral `agentgate_*` roles, a `request_db_credential` broker method mirroring `request_token`, and a background reaper task.

**Tech Stack:** Python 3.11+, asyncpg (new), fastmcp, cryptography/argon2 (existing), pytest + pytest-asyncio.

## Global Constraints

- Every new module starts with `from __future__ import annotations`.
- MCP tool names match `^[a-zA-Z0-9_-]{1,64}$` — underscore form only (e.g. `db_credential_request`), never dots.
- New runtime dependency: `asyncpg>=0.29`. Add to both `requirements.txt` and `pyproject.toml` `dependencies`.
- Ephemeral role names are `agentgate_` + `secrets.token_hex(8)`; they must match `^agentgate_[0-9a-f]+$`. Passwords are `secrets.token_urlsafe(24)` and must match `^[A-Za-z0-9_-]+$`.
- Postgres DDL (`CREATE ROLE`) does NOT accept bind parameters. The only values placed into DDL text are broker-generated and asserted against the safe charsets above; all SQL identifiers are double-quote-quoted. No externally supplied value (resource names from agents, etc.) is ever interpolated into SQL.
- Allowed grant verbs: exactly `SELECT`, `INSERT`, `UPDATE`, `DELETE`. No `ALL`, no DDL, no role management, no column-level grants.
- Grant object identifiers match `^[A-Za-z_][A-Za-z0-9_$]*$`, optionally one `schema.table` qualifier. Grants are validated at `db-add` registration time, not request time.
- The admin Postgres role is non-superuser (`CREATEROLE`); AgentGate never requires superuser. (Operator responsibility; documented, not enforced in code.)
- The generated password appears ONLY in the grant response — never in the audit log, never in an error message. Admin passwords live encrypted in `DbResourceStore` and are not retained after use (inherited `EncryptedStore` behavior).
- All timestamps are timezone-aware UTC (`datetime.datetime.now(datetime.timezone.utc)`), consistent with the rest of the codebase.
- The reaper only ever drops role names matching `^agentgate_[0-9a-f]+$`.
- Config defaults: `DB_CRED_TTL_MINUTES=15` (min 1), `DB_REAP_INTERVAL_SECONDS=30` (min 1), `DB_RESOURCES_PATH=<AGENTGATE_HOME>/db_resources.json`.
- Fail closed: unknown resource, unauthenticated agent, admin-connection failure, mint failure, flood cap, and escalation timeout all produce a structured denial with all secret/connection fields `null`, plus an audit `denied` row and a generic agent-facing reason.

---

## File Structure

- `broker/db_grants.py` (new) — pure grant validation + SQL statement building.
- `broker/db_executor.py` (new) — `AdminDsn`, `SqlStatement`, `DbExecutor` protocol, `AsyncpgExecutor`.
- `broker/db_resource_store.py` (new) — `DbResource` dataclass + `DbResourceStore(EncryptedStore)`.
- `broker/db_broker.py` (new) — role/password generation, `build_mint_statements`, `mint`, `reap`, `MintedCred`.
- `broker/config.py` (modify) — 3 new fields.
- `broker/audit.py` (modify) — optional `username`/`grants` params.
- `broker/mcp_server.py` (modify) — `Broker.__init__` gains `db_resources`/`db_executor`; `request_db_credential`/`_grant_db`/`_escalate_db`; register `db_credential_request` tool.
- `broker/main.py` (modify) — reaper task + `build_broker` wiring.
- `cli/commands.py` (modify) — `db-add`/`db-list`/`db-remove` + operator audit.
- `requirements.txt`, `pyproject.toml`, `.env.example`, `README.md` (modify).
- Tests: `tests/test_db_grants.py`, `tests/test_db_resource_store.py`, `tests/test_db_broker.py`, `tests/test_db_tool.py`, `tests/test_db_cli.py`, `tests/test_db_integration.py` (skip-gated); plus additions to `tests/test_config.py`, `tests/test_audit.py`.

---

### Task 1: Grant validation + SQL building (`db_grants.py`)

**Files:**
- Create: `broker/db_grants.py`
- Test: `tests/test_db_grants.py`

**Interfaces:**
- Consumes: nothing (pure module).
- Produces:
  - `class GrantError(Exception)`
  - `validate_grant(raw: dict) -> dict` — returns a normalized `{"verb": str, "objects": list[str]}`; raises `GrantError` on any violation.
  - `quote_ident(obj: str) -> str` — `schema.table` → `"schema"."table"`.
  - `build_grant_statements(role: str, grants: list[dict]) -> list[str]` — returns ready-to-run `GRANT` SQL strings (role name double-quoted).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_db_grants.py
from __future__ import annotations

import pytest

from broker import db_grants


def test_validate_accepts_allowed_verb_and_identifiers():
    out = db_grants.validate_grant({"verb": "select", "objects": ["public.events", "users"]})
    assert out == {"verb": "SELECT", "objects": ["public.events", "users"]}


@pytest.mark.parametrize("verb", ["ALL", "DROP", "GRANT", "TRUNCATE", "REFERENCES", ""])
def test_validate_rejects_disallowed_verbs(verb):
    with pytest.raises(db_grants.GrantError):
        db_grants.validate_grant({"verb": verb, "objects": ["t"]})


@pytest.mark.parametrize("obj", [
    'events"; DROP ROLE x --',
    "events; DELETE",
    "a.b.c",
    "has space",
    "1nvalid",
    "back`tick",
    "",
])
def test_validate_rejects_bad_identifiers(obj):
    with pytest.raises(db_grants.GrantError):
        db_grants.validate_grant({"verb": "SELECT", "objects": [obj]})


def test_validate_requires_at_least_one_object():
    with pytest.raises(db_grants.GrantError):
        db_grants.validate_grant({"verb": "SELECT", "objects": []})


def test_quote_ident_qualified_and_bare():
    assert db_grants.quote_ident("events") == '"events"'
    assert db_grants.quote_ident("public.events") == '"public"."events"'


def test_build_grant_statements():
    grants = [
        {"verb": "SELECT", "objects": ["public.events", "users"]},
        {"verb": "INSERT", "objects": ["public.audit"]},
    ]
    stmts = db_grants.build_grant_statements("agentgate_ab12", grants)
    assert stmts == [
        'GRANT SELECT ON "public"."events", "users" TO "agentgate_ab12"',
        'GRANT INSERT ON "public"."audit" TO "agentgate_ab12"',
    ]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_db_grants.py -q`
Expected: FAIL (`ModuleNotFoundError: broker.db_grants`).

- [ ] **Step 3: Implement `broker/db_grants.py`**

```python
from __future__ import annotations

import re

_ALLOWED_VERBS = {"SELECT", "INSERT", "UPDATE", "DELETE"}
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")


class GrantError(Exception):
    """Raised when a grant definition is malformed or uses a disallowed verb/identifier."""


def validate_grant(raw: dict) -> dict:
    verb = str(raw.get("verb", "")).upper()
    if verb not in _ALLOWED_VERBS:
        raise GrantError(f"grant verb must be one of {sorted(_ALLOWED_VERBS)}, got {verb!r}")
    objects = raw.get("objects") or []
    if not objects:
        raise GrantError("grant must name at least one object")
    normalized: list[str] = []
    for obj in objects:
        parts = str(obj).split(".")
        if len(parts) not in (1, 2) or not all(_IDENT.match(p) for p in parts):
            raise GrantError(f"invalid object identifier {obj!r}")
        normalized.append(".".join(parts))
    return {"verb": verb, "objects": normalized}


def quote_ident(obj: str) -> str:
    # Callers must have validated obj against _IDENT already; parts cannot
    # contain a double quote, so wrapping is safe.
    return ".".join(f'"{part}"' for part in obj.split("."))


def build_grant_statements(role: str, grants: list[dict]) -> list[str]:
    statements = []
    for grant in grants:
        objects = ", ".join(quote_ident(o) for o in grant["objects"])
        statements.append(f'GRANT {grant["verb"]} ON {objects} TO "{role}"')
    return statements
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_db_grants.py -q`
Expected: PASS (all).

- [ ] **Step 5: Commit**

```bash
git add broker/db_grants.py tests/test_db_grants.py
git commit -m "feat: db grant validation + SQL building (allowlisted verbs, quoted idents)"
```

---

### Task 2: Encrypted DB resource store (`db_resource_store.py`)

**Files:**
- Create: `broker/db_resource_store.py`
- Test: `tests/test_db_resource_store.py`

**Interfaces:**
- Consumes: `broker.encrypted_store.EncryptedStore`, `broker.crypto`.
- Produces:
  - `@dataclass(frozen=True) class DbResource` with fields `name: str`, `host: str`, `port: int`, `dbname: str`, `admin_user: str`, `admin_password: str`, `grants: list[dict]`, `created_at: str`.
  - `class DbResourceStore(EncryptedStore)` with `_SECTION = "db_resources"` and methods `store(resource: DbResource) -> None`, `get(name: str) -> DbResource` (raises `KeyError`), `delete(name: str) -> None` (raises `KeyError`), `list_names() -> list[str]`, `list_metadata() -> list[dict]` (no `admin_password`).

**Note:** `admin_password` is the only encrypted field; `host`/`port`/`dbname`/`admin_user`/`grants`/`created_at` are clear (mirrors `ConnectionStore`, where only secrets are encrypted).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_db_resource_store.py
from __future__ import annotations

import pytest

from broker.crypto import CryptoDecryptionError
from broker.db_resource_store import DbResource, DbResourceStore


def _res() -> DbResource:
    return DbResource(
        name="analytics-ro", host="db.internal", port=5432, dbname="analytics",
        admin_user="agentgate_admin", admin_password="s3cret-admin",
        grants=[{"verb": "SELECT", "objects": ["public.events"]}],
        created_at="2026-07-02T10:00:00+00:00",
    )


def test_store_and_get_roundtrip(tmp_path):
    store = DbResourceStore(str(tmp_path / "db.json"), "pw")
    store.store(_res())
    got = store.get("analytics-ro")
    assert got.host == "db.internal"
    assert got.admin_password == "s3cret-admin"
    assert got.grants == [{"verb": "SELECT", "objects": ["public.events"]}]


def test_admin_password_encrypted_on_disk(tmp_path):
    path = tmp_path / "db.json"
    DbResourceStore(str(path), "pw").store(_res())
    raw = path.read_text(encoding="utf-8")
    assert "s3cret-admin" not in raw


def test_list_metadata_has_no_admin_password(tmp_path):
    store = DbResourceStore(str(tmp_path / "db.json"), "pw")
    store.store(_res())
    meta = store.list_metadata()
    assert meta == [{
        "name": "analytics-ro", "host": "db.internal", "port": 5432,
        "dbname": "analytics", "grants": [{"verb": "SELECT", "objects": ["public.events"]}],
        "created_at": "2026-07-02T10:00:00+00:00",
    }]


def test_delete_and_missing(tmp_path):
    store = DbResourceStore(str(tmp_path / "db.json"), "pw")
    store.store(_res())
    store.delete("analytics-ro")
    assert store.list_names() == []
    with pytest.raises(KeyError):
        store.get("analytics-ro")
    with pytest.raises(KeyError):
        store.delete("analytics-ro")


def test_wrong_password_fails_closed(tmp_path):
    path = str(tmp_path / "db.json")
    DbResourceStore(path, "pw").store(_res())
    with pytest.raises(CryptoDecryptionError):
        DbResourceStore(path, "WRONG").get("analytics-ro")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_db_resource_store.py -q`
Expected: FAIL (`ModuleNotFoundError: broker.db_resource_store`).

- [ ] **Step 3: Implement `broker/db_resource_store.py`**

```python
from __future__ import annotations

from dataclasses import dataclass

from broker import crypto
from broker.encrypted_store import EncryptedStore


@dataclass(frozen=True)
class DbResource:
    name: str
    host: str
    port: int
    dbname: str
    admin_user: str
    admin_password: str
    grants: list[dict]
    created_at: str


class DbResourceStore(EncryptedStore):
    _SECTION = "db_resources"

    def store(self, resource: DbResource) -> None:
        self._entries()[resource.name] = {
            "host": resource.host,
            "port": resource.port,
            "dbname": resource.dbname,
            "admin_user": resource.admin_user,
            "admin_password": crypto.encrypt(self._key, resource.admin_password),
            "grants": [dict(g) for g in resource.grants],
            "created_at": resource.created_at,
        }
        self._write(self._data)

    def get(self, name: str) -> DbResource:
        entries = self._entries()
        if name not in entries:
            raise KeyError(name)
        rec = entries[name]
        return DbResource(
            name=name,
            host=rec["host"],
            port=rec["port"],
            dbname=rec["dbname"],
            admin_user=rec["admin_user"],
            admin_password=crypto.decrypt(self._key, rec["admin_password"]),
            grants=[dict(g) for g in rec["grants"]],
            created_at=rec["created_at"],
        )

    def delete(self, name: str) -> None:
        entries = self._entries()
        if name not in entries:
            raise KeyError(name)
        del entries[name]
        self._write(self._data)

    def list_names(self) -> list[str]:
        return sorted(self._entries().keys())

    def list_metadata(self) -> list[dict]:
        return [
            {
                "name": name,
                "host": rec["host"],
                "port": rec["port"],
                "dbname": rec["dbname"],
                "grants": [dict(g) for g in rec["grants"]],
                "created_at": rec["created_at"],
            }
            for name, rec in sorted(self._entries().items())
        ]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_db_resource_store.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add broker/db_resource_store.py tests/test_db_resource_store.py
git commit -m "feat: encrypted DbResourceStore (admin password encrypted, metadata secret-free)"
```

---

### Task 3: Config additions

**Files:**
- Modify: `broker/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: existing `Config`, `_DEFAULTS`, `_default_paths`, `_require_int`, `_require_non_empty`.
- Produces: `Config` gains `db_resources_path: str`, `db_cred_ttl_minutes: int = 15`, `db_reap_interval_seconds: int = 30`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_config.py`)

```python
def test_db_defaults():
    cfg = Config.from_env({})
    assert cfg.db_resources_path.endswith("db_resources.json")
    assert cfg.db_cred_ttl_minutes == 15
    assert cfg.db_reap_interval_seconds == 30


def test_db_cred_ttl_must_be_positive():
    import pytest
    from broker.config import ConfigError
    with pytest.raises(ConfigError):
        Config.from_env({"DB_CRED_TTL_MINUTES": "0"})


def test_db_resources_path_follows_agentgate_home():
    import os
    cfg = Config.from_env({"AGENTGATE_HOME": os.path.join("srv", "ag")})
    assert cfg.db_resources_path == os.path.join("srv", "ag", "db_resources.json")
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_config.py -k db -q`
Expected: FAIL (`AttributeError: 'Config' object has no attribute 'db_resources_path'`).

- [ ] **Step 3: Implement**

In `broker/config.py`, add to `_DEFAULTS` (after `"ESCALATION_MAX_PENDING": "3",`):

```python
    "DB_CRED_TTL_MINUTES": "15",
    "DB_REAP_INTERVAL_SECONDS": "30",
```

In `_default_paths`, add to the returned dict:

```python
        "DB_RESOURCES_PATH": os.path.join(base, "db_resources.json"),
```

Add dataclass fields (after `escalation_max_pending: int = 3`):

```python
    db_resources_path: str = os.path.join("data", "db_resources.json")
    db_cred_ttl_minutes: int = 15
    db_reap_interval_seconds: int = 30
```

Add to the `cls(...)` call in `from_env` (after the `escalation_max_pending=...` line):

```python
            db_resources_path=_require_non_empty(get("DB_RESOURCES_PATH"), "DB_RESOURCES_PATH"),
            db_cred_ttl_minutes=_require_int(get("DB_CRED_TTL_MINUTES"), "DB_CRED_TTL_MINUTES", minimum=1),
            db_reap_interval_seconds=_require_int(
                get("DB_REAP_INTERVAL_SECONDS"), "DB_REAP_INTERVAL_SECONDS", minimum=1
            ),
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_config.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add broker/config.py tests/test_config.py
git commit -m "feat: config for DB broker (resources path, cred TTL, reap interval)"
```

---

### Task 4: DB executor seam + mint/reap logic (`db_executor.py`, `db_broker.py`)

**Files:**
- Create: `broker/db_executor.py`, `broker/db_broker.py`
- Test: `tests/test_db_broker.py`

**Interfaces:**
- Consumes: `broker.db_grants.build_grant_statements`, `broker.db_resource_store.DbResource`.
- Produces:
  - `broker/db_executor.py`: `@dataclass(frozen=True) AdminDsn(host, port, dbname, user, password)`; `@dataclass(frozen=True) SqlStatement(sql: str, params: tuple = ())`; `class DbExecutor(Protocol)` with `async run_admin(dsn, statements)`, `async list_expired_roles(dsn, pattern) -> list[str]`, `async drop_role(dsn, role)`; `class AsyncpgExecutor` implementing it.
  - `broker/db_broker.py`: `ROLE_PREFIX = "agentgate_"`; `@dataclass(frozen=True) MintedCred(host, port, dbname, username, password, expires_at)`; `generate_role_name() -> str`; `generate_password() -> str`; `admin_dsn(resource) -> AdminDsn`; `build_mint_statements(role, password, resource, expires_at) -> list[SqlStatement]`; `async mint(executor, resource, ttl_minutes) -> MintedCred`; `async reap(executor, resource) -> list[str]`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_db_broker.py
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
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_db_broker.py -q`
Expected: FAIL (`ModuleNotFoundError: broker.db_broker`).

- [ ] **Step 3a: Implement `broker/db_executor.py`**

```python
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
```

- [ ] **Step 3b: Implement `broker/db_broker.py`**

```python
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
    assert _ROLE_RE.match(role), "generated role name failed safe-charset check"
    assert _PW_RE.match(password), "generated password failed safe-charset check"
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
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_db_broker.py -q`
Expected: PASS (async tests run via `asyncio_mode = auto`).

- [ ] **Step 5: Commit**

```bash
git add broker/db_executor.py broker/db_broker.py tests/test_db_broker.py
git commit -m "feat: db executor seam + mint/reap (safe-charset DDL, namespaced reaper)"
```

---

### Task 5: Audit fields + broker request path + MCP tool

**Files:**
- Modify: `broker/audit.py`, `broker/mcp_server.py`
- Test: `tests/test_audit.py`, `tests/test_db_tool.py`

**Interfaces:**
- Consumes: `broker.db_broker.mint`, `broker.db_resource_store.DbResourceStore`, `broker.db_executor.DbExecutor`, existing `Broker._authenticate`/`_flooded`/`_current_engine`/`state.read_mode`/`self.approvals`.
- Produces:
  - `AuditLogger.log(...)` gains `username: str | None = None`, `grants: list[str] | None = None` (added to the entry only when provided).
  - `Broker.__init__` gains `db_resources: DbResourceStore | None = None`, `db_executor: DbExecutor | None = None`.
  - `Broker.request_db_credential(agent, agent_key, resource) -> dict` (return keys: `granted, host, port, dbname, username, password, expires_at, reason`; secret/connection fields `null` on denial).
  - MCP tool `db_credential_request(agent, agent_key, resource)`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_audit.py`:

```python
def test_log_accepts_username_and_grants(tmp_path):
    import json
    from broker.audit import AuditLogger
    path = tmp_path / "audit.log"
    AuditLogger(str(path)).log(
        agent="claude-code", credential_requested="analytics-ro", policy_matched="p",
        decision="approved", mode="auto", token_expiry="2026-07-02T10:15:00+00:00",
        username="agentgate_ab12", grants=['GRANT SELECT ON "public"."events" TO "agentgate_ab12"'],
    )
    entry = json.loads(path.read_text().strip())
    assert entry["username"] == "agentgate_ab12"
    assert entry["grants"] == ['GRANT SELECT ON "public"."events" TO "agentgate_ab12"']


def test_log_omits_username_grants_when_absent(tmp_path):
    import json
    from broker.audit import AuditLogger
    path = tmp_path / "audit.log"
    AuditLogger(str(path)).log(
        agent="a", credential_requested="k", policy_matched="p",
        decision="denied", mode="auto", token_expiry=None,
    )
    entry = json.loads(path.read_text().strip())
    assert "username" not in entry and "grants" not in entry
```

Create `tests/test_db_tool.py`:

```python
from __future__ import annotations

import re
import textwrap

import pytest
from fastmcp import Client

from broker import db_broker
from broker.agent_store import AgentStore
from broker.approval import ApprovalQueue
from broker.audit import AuditLogger
from broker.config import Config
from broker.credential_store import CredentialStore
from broker.db_resource_store import DbResource, DbResourceStore
from broker.mcp_server import Broker, build_mcp
from broker.policy_engine import PolicyEngine


class FakeExecutor:
    def __init__(self, run_raises=False):
        self.run_raises = run_raises
        self.calls = []

    async def run_admin(self, dsn, statements):
        if self.run_raises:
            raise RuntimeError("admin connection refused")
        self.calls.append((dsn, statements))

    async def list_expired_roles(self, dsn, pattern):
        return []

    async def drop_role(self, dsn, role):
        pass


def _wire(tmp_path, run_raises=False):
    pol = tmp_path / "policies.yaml"
    pol.write_text(textwrap.dedent("""
        policies:
          - name: cc-analytics
            agent: claude-code
            credential: analytics-ro
            auto_approve: true
          - name: default-deny
            agent: "*"
            credential: "*"
            auto_approve: false
            escalate: true
    """))
    cfg = Config.from_env({
        "POLICIES_PATH": str(pol), "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTS_PATH": str(tmp_path / "agents.json"),
        "DB_RESOURCES_PATH": str(tmp_path / "db.json"),
    })
    agents = AgentStore(cfg.agents_path, "pw")
    key = agents.register("claude-code")
    resources = DbResourceStore(cfg.db_resources_path, "pw")
    resources.store(DbResource(
        name="analytics-ro", host="db", port=5432, dbname="analytics",
        admin_user="agentgate_admin", admin_password="admin-pw",
        grants=[{"verb": "SELECT", "objects": ["public.events"]}],
        created_at="2026-07-02T10:00:00+00:00",
    ))
    broker = Broker(
        config=cfg, store=CredentialStore(cfg.credentials_path, "pw"),
        engine=PolicyEngine.from_file(cfg.policies_path),
        audit=AuditLogger(cfg.logs_path), approvals=ApprovalQueue(),
        agents=agents, db_resources=resources, db_executor=FakeExecutor(run_raises),
    )
    return broker, key, cfg, tmp_path


async def test_db_credential_request_grants_and_audits(tmp_path):
    broker, key, cfg, tp = _wire(tmp_path)
    res = await broker.request_db_credential("claude-code", key, "analytics-ro")
    assert res["granted"] is True
    assert res["username"].startswith("agentgate_")
    assert res["password"]
    assert res["host"] == "db" and res["dbname"] == "analytics"
    log = (tp / "audit.log").read_text()
    assert res["password"] not in log          # password never audited
    assert '"username": "agentgate_' in log     # username IS audited
    assert '"decision": "approved"' in log


async def test_db_credential_request_unknown_agent_denied(tmp_path):
    broker, key, cfg, tp = _wire(tmp_path)
    res = await broker.request_db_credential("ghost", "bad", "analytics-ro")
    assert res["granted"] is False
    assert res["password"] is None
    assert broker.approvals.pending_count() == 0


async def test_db_credential_request_unknown_resource_denied(tmp_path):
    broker, key, cfg, tp = _wire(tmp_path)
    # 'nope' matches default-deny -> escalate -> approve -> resource missing -> fail closed.
    import asyncio
    task = asyncio.create_task(broker.request_db_credential("claude-code", key, "nope"))
    await asyncio.sleep(0.05)
    broker.approvals.resolve(broker.approvals.get_pending(), True)
    res = await task
    assert res["granted"] is False
    assert "nope" in res["reason"]


async def test_db_credential_request_mint_failure_fails_closed(tmp_path):
    broker, key, cfg, tp = _wire(tmp_path, run_raises=True)
    res = await broker.request_db_credential("claude-code", key, "analytics-ro")
    assert res["granted"] is False
    assert res["password"] is None
    assert "admin connection refused" not in res["reason"]  # generic reason only
    log = (tp / "audit.log").read_text()
    assert '"decision": "denied"' in log


async def test_tool_registered_and_spec_compliant(tmp_path):
    broker, key, cfg, tp = _wire(tmp_path)
    mcp = build_mcp(broker)
    async with Client(mcp) as client:
        names = [t.name for t in await client.list_tools()]
        assert "db_credential_request" in names
        assert all(re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", n) for n in names)
        res = await client.call_tool("db_credential_request", {
            "agent": "claude-code", "agent_key": key, "resource": "analytics-ro"})
        assert res.data["granted"] is True
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_db_tool.py tests/test_audit.py -q`
Expected: FAIL (`TypeError` on unexpected `username`/`db_resources` kwargs; missing `request_db_credential`).

- [ ] **Step 3a: Extend `broker/audit.py`**

Change the `log` signature and entry construction. Current signature ends with `scopes: list[str] | None = None`. Add two params and two conditional entries:

```python
    def log(
        self,
        *,
        agent: str,
        credential_requested: str,
        policy_matched: str,
        decision: str,
        mode: str,
        token_expiry: str | None,
        scopes: list[str] | None = None,
        username: str | None = None,
        grants: list[str] | None = None,
    ) -> None:
        if decision not in _VALID_DECISIONS:
            raise ValueError(f"decision must be one of {_VALID_DECISIONS}, got {decision!r}")
        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "agent": agent,
            "credential_requested": credential_requested,
            "policy_matched": policy_matched,
            "decision": decision,
            "mode": mode,
            "token_expiry": token_expiry,
        }
        if scopes is not None:
            entry["scopes"] = list(scopes)
        if username is not None:
            entry["username"] = username
        if grants is not None:
            entry["grants"] = list(grants)
        self._append(entry)
```

- [ ] **Step 3b: Extend `Broker` in `broker/mcp_server.py`**

Add imports near the other broker imports:

```python
from broker import db_broker
from broker.db_executor import DbExecutor
from broker.db_resource_store import DbResourceStore
```

Add constructor params. In `Broker.__init__`, extend the signature (after `agents: AgentStore | None = None,`) and body:

```python
        db_resources: DbResourceStore | None = None,
        db_executor: DbExecutor | None = None,
```
```python
        self.db_resources = db_resources
        self.db_executor = db_executor
```

Add the request path (place after `_grant_token`/`_escalate_token`, before `list_policies`):

```python
    @staticmethod
    def _db_deny(reason: str) -> dict:
        return {
            "granted": False, "host": None, "port": None, "dbname": None,
            "username": None, "password": None, "expires_at": None, "reason": reason,
        }

    async def request_db_credential(self, agent: str, agent_key: str, resource: str) -> dict:
        self.total_requests += 1
        mode = state.read_mode(self.config.state_path)

        if not self._authenticate(agent, agent_key, resource, mode):
            return self._db_deny("unknown agent or invalid agent key")

        if mode == "manual":
            return await self._escalate_db(agent, resource, mode, "manual-mode")

        decision = self._current_engine().evaluate(agent, resource)
        if decision.auto_approve:
            return await self._grant_db(agent, resource, mode, decision.policy_name)
        if not decision.escalate:
            self.audit.log(
                agent=agent, credential_requested=resource,
                policy_matched=decision.policy_name, decision="denied",
                mode=mode, token_expiry=None,
            )
            return self._db_deny(f"denied by policy '{decision.policy_name}'")
        return await self._escalate_db(agent, resource, mode, decision.policy_name)

    async def _grant_db(self, agent: str, resource: str, mode: str, policy_name: str) -> dict:
        if self.db_resources is None:
            res = None
        else:
            try:
                res = self.db_resources.get(resource)
            except KeyError:
                res = None
        if res is None or self.db_executor is None:
            self.audit.log(
                agent=agent, credential_requested=resource, policy_matched=policy_name,
                decision="denied", mode=mode, token_expiry=None,
            )
            return self._db_deny(f"unknown database resource '{resource}'")

        try:
            cred = await db_broker.mint(self.db_executor, res, self.config.db_cred_ttl_minutes)
        except Exception:
            # Fail closed: never leak the driver/DSN error to the agent, always audit.
            self.audit.log(
                agent=agent, credential_requested=resource, policy_matched=policy_name,
                decision="denied", mode=mode, token_expiry=None,
            )
            return self._db_deny(f"could not provision database credential for '{resource}'")

        applied = []
        for grant in res.grants:
            applied.append(f'{grant["verb"]} ON {", ".join(grant["objects"])}')
        self.audit.log(
            agent=agent, credential_requested=resource, policy_matched=policy_name,
            decision="approved", mode=mode, token_expiry=cred.expires_at,
            username=cred.username, grants=applied,
        )
        return {
            "granted": True, "host": cred.host, "port": cred.port, "dbname": cred.dbname,
            "username": cred.username, "password": cred.password,
            "expires_at": cred.expires_at,
            "reason": f"auto-approved by policy '{policy_name}'",
        }

    async def _escalate_db(self, agent: str, resource: str, mode: str, policy_name: str) -> dict:
        if self._flooded(agent, resource, mode, policy_name):
            return self._db_deny("too many requests pending operator approval")
        self.escalated_requests += 1
        self.audit.log(
            agent=agent, credential_requested=resource, policy_matched=policy_name,
            decision="escalated", mode=mode, token_expiry=None,
        )
        try:
            approved = await self.approvals.submit(
                agent, resource, timeout=self.config.escalation_timeout_seconds or None
            )
        except asyncio.TimeoutError:
            self.audit.log(
                agent=agent, credential_requested=resource, policy_matched=policy_name,
                decision="expired", mode=mode, token_expiry=None,
            )
            return self._db_deny("escalation timed out")
        if approved:
            return await self._grant_db(agent, resource, mode, f"manual:{policy_name}")
        self.audit.log(
            agent=agent, credential_requested=resource, policy_matched=policy_name,
            decision="denied", mode=mode, token_expiry=None,
        )
        return self._db_deny("denied by operator")
```

Register the tool in `build_mcp` (after the `token_request` tool, before `return mcp`):

```python
    @mcp.tool(name="db_credential_request")
    async def db_credential_request(agent: str, agent_key: str, resource: str) -> dict:
        return await broker.request_db_credential(agent, agent_key, resource)
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_db_tool.py tests/test_audit.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add broker/audit.py broker/mcp_server.py tests/test_db_tool.py tests/test_audit.py
git commit -m "feat: db_credential_request broker path + MCP tool; audit username/grants"
```

---

### Task 6: Reaper task + broker wiring (`main.py`)

**Files:**
- Modify: `broker/main.py`
- Test: `tests/test_main.py`

**Interfaces:**
- Consumes: `broker.db_broker.reap`, `broker.db_resource_store.DbResourceStore`, `broker.db_executor.AsyncpgExecutor`, existing `build_broker`, `run`.
- Produces: `build_broker` wires `db_resources` + `db_executor` into `Broker`; a `_reaper_loop(broker)` coroutine; `run` starts it as a background task.

- [ ] **Step 1: Write the failing test** (append to `tests/test_main.py`)

```python
@pytest.mark.asyncio
async def test_reaper_loop_reaps_each_resource_once_then_cancels(tmp_path, monkeypatch):
    import asyncio
    from broker import main as m
    from broker.db_resource_store import DbResource, DbResourceStore

    cfg = Config.from_env({
        "POLICIES_PATH": str(tmp_path / "p.yaml"),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTS_PATH": str(tmp_path / "agents.json"),
        "DB_RESOURCES_PATH": str(tmp_path / "db.json"),
        "DB_REAP_INTERVAL_SECONDS": "1",
    })
    (tmp_path / "p.yaml").write_text(
        'policies:\n  - name: d\n    agent: "*"\n    credential: "*"\n'
        "    auto_approve: false\n    escalate: true\n")
    resources = DbResourceStore(cfg.db_resources_path, "pw")
    resources.store(DbResource(
        name="r", host="h", port=5432, dbname="d", admin_user="a",
        admin_password="pw", grants=[], created_at="2026-07-02T10:00:00+00:00"))

    reaped = []

    async def fake_reap(executor, resource):
        reaped.append(resource.name)
        return ["agentgate_dead"]
    monkeypatch.setattr(m.db_broker, "reap", fake_reap)

    broker = m.build_broker(cfg, "pw")
    # Drive one sweep quickly instead of waiting the full interval.
    monkeypatch.setattr(m.asyncio, "sleep", lambda _s: asyncio.sleep(0))
    task = asyncio.create_task(m._reaper_loop(broker))
    await asyncio.sleep(0.05)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    assert "r" in reaped
    log = (tmp_path / "audit.log").read_text()
    assert '"action": "db-reap"' in log
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_main.py -k reaper -q`
Expected: FAIL (`AttributeError: module 'broker.main' has no attribute '_reaper_loop'`).

- [ ] **Step 3: Implement**

In `broker/main.py`, add imports at the top (with the other `broker.` imports):

```python
from broker import db_broker
from broker.db_executor import AsyncpgExecutor
from broker.db_resource_store import DbResourceStore
```

In `build_broker`, extend the `Broker(...)` call (add after `agents=...`):

```python
        db_resources=DbResourceStore(config.db_resources_path, master_password),
        db_executor=AsyncpgExecutor(),
```

Add the reaper loop (near `_cli_loop`):

```python
async def _reaper_loop(broker: Broker) -> None:
    """Periodically drop expired agentgate_* roles for every registered
    resource. Stateless — recovers dangling roles after a restart. Never dies
    on a per-resource error."""
    while True:
        await asyncio.sleep(broker.config.db_reap_interval_seconds)
        if broker.db_resources is None or broker.db_executor is None:
            continue
        for name in broker.db_resources.list_names():
            try:
                resource = broker.db_resources.get(name)
                for role in await db_broker.reap(broker.db_executor, resource):
                    broker.audit.log_operator(action="db-reap", subject=role)
            except Exception:
                continue
```

In `run`, start it alongside the CLI and server tasks. Change the task set:

```python
    cli_task = asyncio.create_task(_cli_loop(broker))
    reaper_task = asyncio.create_task(_reaper_loop(broker))
    server_task = asyncio.create_task(
        mcp.run_async(
            transport="http",
            host=config.mcp_host,
            port=config.mcp_port,
            show_banner=False,
            middleware=[
                Middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts(config))
            ],
        )
    )
    done, pending = await asyncio.wait(
        {cli_task, reaper_task, server_task}, return_when=asyncio.FIRST_COMPLETED
    )
    for task in pending:
        task.cancel()
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_main.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add broker/main.py tests/test_main.py
git commit -m "feat: background reaper task + wire DbResourceStore/AsyncpgExecutor into broker"
```

---

### Task 7: CLI `db-add` / `db-list` / `db-remove`

**Files:**
- Modify: `cli/commands.py`
- Test: `tests/test_db_cli.py`

**Interfaces:**
- Consumes: `broker.db_resource_store.DbResource`/`DbResourceStore`, `broker.db_grants.validate_grant`/`GrantError`, `broker.audit.AuditLogger`, existing `_password`, `build_parser`, `run`.
- Produces: subcommands `db-add <name> --host --port --dbname --admin-user [--grant ...]`, `db-list`, `db-remove <name>`. Admin password read from `AGENTGATE_DB_ADMIN_PASSWORD` or (TTY) `getpass`, else stdin — never argv. `--grant` is repeatable, format `VERB:obj[,obj...]`. Grants validated at add time; invalid → exit 2, nothing stored. `db-add`/`db-remove` audited as operator actions.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_db_cli.py
from __future__ import annotations

import textwrap

from broker.config import Config
from broker.db_resource_store import DbResourceStore
from cli import commands


def _cfg(tmp_path):
    (tmp_path / "p.yaml").write_text(textwrap.dedent("""
        policies:
          - name: d
            agent: "*"
            credential: "*"
            auto_approve: false
            escalate: true
    """))
    return Config.from_env({
        "POLICIES_PATH": str(tmp_path / "p.yaml"),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTS_PATH": str(tmp_path / "agents.json"),
        "DB_RESOURCES_PATH": str(tmp_path / "db.json"),
    })


def test_db_add_list_remove(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path)
    monkeypatch.setenv("AGENTGATE_DB_ADMIN_PASSWORD", "admin-pw")
    rc = commands.run([
        "db-add", "analytics-ro", "--host", "db", "--port", "5432",
        "--dbname", "analytics", "--admin-user", "agentgate_admin",
        "--grant", "SELECT:public.events,users",
    ], config=cfg, master_password="pw")
    assert rc == 0

    store = DbResourceStore(cfg.db_resources_path, "pw")
    res = store.get("analytics-ro")
    assert res.admin_password == "admin-pw"
    assert res.grants == [{"verb": "SELECT", "objects": ["public.events", "users"]}]

    assert commands.run(["db-list"], config=cfg, master_password="pw") == 0
    out = capsys.readouterr().out
    assert "analytics-ro" in out and "admin-pw" not in out  # password never printed

    assert commands.run(["db-remove", "analytics-ro"], config=cfg, master_password="pw") == 0
    assert DbResourceStore(cfg.db_resources_path, "pw").list_names() == []

    log = (tmp_path / "audit.log").read_text()
    assert '"action": "db-add"' in log and '"action": "db-remove"' in log
    assert "admin-pw" not in log


def test_db_add_rejects_bad_grant(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    monkeypatch.setenv("AGENTGATE_DB_ADMIN_PASSWORD", "admin-pw")
    rc = commands.run([
        "db-add", "bad", "--host", "db", "--port", "5432",
        "--dbname", "d", "--admin-user", "a",
        "--grant", "DROP:public.events",
    ], config=cfg, master_password="pw")
    assert rc == 2
    assert DbResourceStore(cfg.db_resources_path, "pw").list_names() == []
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_db_cli.py -q`
Expected: FAIL (`SystemExit: 2` from argparse — unknown subcommand `db-add`).

- [ ] **Step 3: Implement**

In `cli/commands.py`, add imports:

```python
from broker.db_grants import GrantError, validate_grant
from broker.db_resource_store import DbResource, DbResourceStore
```

In `build_parser`, add after the `disconnect` subparser:

```python
    da = sub.add_parser("db-add", help="register a PostgreSQL resource")
    da.add_argument("name")
    da.add_argument("--host", required=True)
    da.add_argument("--port", type=int, required=True)
    da.add_argument("--dbname", required=True)
    da.add_argument("--admin-user", required=True, dest="admin_user")
    da.add_argument("--grant", action="append", default=[], dest="grants",
                    help='repeatable, format "VERB:obj[,obj...]"')
    sub.add_parser("db-list", help="list registered DB resources (no secrets)")
    dr = sub.add_parser("db-remove", help="remove a DB resource")
    dr.add_argument("name")
```

Add command handling in `run` (before the final `return 2`):

```python
    if args.command == "db-add":
        admin_password = os.environ.get("AGENTGATE_DB_ADMIN_PASSWORD")
        if not admin_password:
            admin_password = (
                getpass.getpass(f"admin password for '{args.name}': ")
                if sys.stdin.isatty() else sys.stdin.readline().rstrip("\n")
            )
        try:
            grants = [_parse_grant(g) for g in args.grants]
        except GrantError as exc:
            print(f"invalid grant: {exc}", file=sys.stderr)
            return 2
        DbResourceStore(config.db_resources_path, _password(master_password)).store(DbResource(
            name=args.name, host=args.host, port=args.port, dbname=args.dbname,
            admin_user=args.admin_user, admin_password=admin_password, grants=grants,
            created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        ))
        AuditLogger(config.logs_path).log_operator(action="db-add", subject=args.name)
        print(f"registered db resource '{args.name}'")
        return 0

    if args.command == "db-list":
        store = DbResourceStore(config.db_resources_path, _password(master_password))
        for meta in store.list_metadata():
            grants = "; ".join(f'{g["verb"]} {",".join(g["objects"])}' for g in meta["grants"])
            print(f"{meta['name']}  {meta['host']}:{meta['port']}/{meta['dbname']}  [{grants}]")
        return 0

    if args.command == "db-remove":
        store = DbResourceStore(config.db_resources_path, _password(master_password))
        try:
            store.delete(args.name)
        except KeyError:
            print(f"no such db resource '{args.name}'", file=sys.stderr)
            return 1
        AuditLogger(config.logs_path).log_operator(action="db-remove", subject=args.name)
        print(f"removed db resource '{args.name}'")
        return 0
```

Add the grant parser helper (near the bottom, beside `_run_connect`):

```python
def _parse_grant(raw: str) -> dict:
    # "VERB:obj[,obj...]" -> validated {"verb", "objects"}.
    verb, _, objs = raw.partition(":")
    objects = [o.strip() for o in objs.split(",") if o.strip()]
    return validate_grant({"verb": verb.strip(), "objects": objects})
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_db_cli.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cli/commands.py tests/test_db_cli.py
git commit -m "feat: CLI db-add/db-list/db-remove with grant validation + operator audit"
```

---

### Task 8: Dependency, docs, and integration test

**Files:**
- Modify: `requirements.txt`, `pyproject.toml`, `.env.example`, `README.md`
- Create: `tests/test_db_integration.py`

**Interfaces:**
- Consumes: everything above; `AsyncpgExecutor`, `DbResourceStore`, `db_broker`.
- Produces: `asyncpg` dependency; docs for the DB broker; a skip-gated real-Postgres end-to-end test.

- [ ] **Step 1: Write the integration test (skip-gated)**

```python
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
```

- [ ] **Step 2: Run to verify it skips cleanly**

Run: `python -m pytest tests/test_db_integration.py -q`
Expected: `1 skipped` (no `AGENTGATE_TEST_PG_DSN` set). If a throwaway Postgres is available, set the DSN and confirm PASS.

- [ ] **Step 3: Add dependency + docs**

`requirements.txt` — add:
```
asyncpg>=0.29
```

`pyproject.toml` — add `"asyncpg>=0.29",` to the `dependencies` list.

`.env.example` — add after the OAuth block:
```
# PostgreSQL infra broker: encrypted resource store, ephemeral-role TTL, and
# the reaper sweep cadence. Register resources with `agentgate db-add`.
# DB_RESOURCES_PATH=./data/db_resources.json
DB_CRED_TTL_MINUTES=15
DB_REAP_INTERVAL_SECONDS=30

# Set ONLY when running `agentgate db-add` (read at add time, stored encrypted;
# never passed as a command-line argument):
# AGENTGATE_DB_ADMIN_PASSWORD=
```

`README.md` — add a "PostgreSQL Infra Broker" section after the OAuth Broker section covering: the model (ephemeral scoped roles, never a standing credential); one-time operator setup (`CREATE ROLE agentgate_admin WITH CREATEROLE`, granting it only what it may delegate `WITH GRANT OPTION`, non-superuser); `agentgate db-add analytics-ro --host … --grant "SELECT:public.events"`; the `db_credential_request(agent, agent_key, resource)` tool and its `{granted, host, port, dbname, username, password, expires_at, reason}` shape; TTL + reaper behavior (block-new-logins + background reap, open sessions end naturally); and the residual-risk note (AgentGate holds a CREATEROLE credential and authors grants). Add `db_credential_request` to the MCP tool list (making 7 tools). Add the three new env vars to the ECS/paths section.

- [ ] **Step 4: Run the full suite**

Run: `python -m pytest -q`
Expected: PASS (all prior tests plus the new ones; integration test skipped).

- [ ] **Step 5: Commit**

```bash
git add requirements.txt pyproject.toml .env.example README.md tests/test_db_integration.py
git commit -m "feat: asyncpg dependency, DB broker docs, skip-gated real-Postgres integration test"
```

---

## Self-Review

**Spec coverage:**
- Engine = PostgreSQL, ephemeral roles → Tasks 4, 8. ✓
- Grants authored from resource definition (policy engine untouched) → Tasks 1, 2, 5 (policy engine not modified). ✓
- Dedicated CREATEROLE admin in encrypted store → Task 2 (`admin_password` encrypted); documented setup in Task 8. ✓
- Block-new-logins + stateless reaper (agentgate_ prefix, VALID UNTIL) → Task 4 (`reap`, `_EXPIRED_PATTERN`, namespace guard), Task 6 (loop). ✓
- Reuse auth/policy/escalation/audit/HTTP unchanged → Task 5 (`request_db_credential` mirrors `request_token`; `_authenticate`/`_flooded`/`_current_engine` reused). ✓
- SQL-injection defenses (allowlist verbs, identifier regex, quoting, no untrusted interpolation, validation at add time) → Task 1 + Task 4 assertions. ✓
- Fail-closed paths (unknown resource, admin failure→rollback via transaction, generic reason, unauthenticated, flood, timeout) → Tasks 4, 5. ✓
- Secret hygiene (password only in response, never audited) → Task 5 tests assert password absent from log; audit records username+grants only. ✓
- Config (DB_RESOURCES_PATH, DB_CRED_TTL_MINUTES, DB_REAP_INTERVAL_SECONDS) → Task 3. ✓
- CLI db-add/db-list/db-remove + operator audit → Task 7. ✓
- Integration test (skip-gated) → Task 8. ✓
- `.gitattributes` export-ignore → already committed with the spec (b9b261c); not repeated here.

**Placeholder scan:** none (all steps carry concrete code/commands). The only prose-only step is the README section in Task 8, which enumerates exact required content.

**Type consistency:** `MintedCred` fields (`host/port/dbname/username/password/expires_at`) match `request_db_credential`'s return keys and the tool test. `DbResource` fields match `DbResourceStore` and the CLI/tool wiring. `SqlStatement(sql, params)` consistent across executor + `build_mint_statements`. `validate_grant` output `{"verb","objects"}` consistent across Tasks 1, 7, and audit-grant formatting in Task 5. Audit `log(... username=, grants=)` signature matches its callers.

**Note for the implementer:** `asyncio_mode = auto` (pytest.ini) means async test functions need no decorator; the few `@pytest.mark.asyncio` uses in existing files are harmless but not required.
