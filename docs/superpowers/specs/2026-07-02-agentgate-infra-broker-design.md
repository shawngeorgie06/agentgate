# AgentGate Infra Broker (PostgreSQL) — Design Spec

**Status:** approved for planning (2026-07-02)
**Scope:** V2 subsystem #2 of 3 (OAuth broker shipped; SaaS/browser broker deferred).

## Goal

Let an AI agent obtain **short-lived, scoped PostgreSQL access** without ever
holding a standing database credential. The agent requests a named database
resource; AgentGate mints a fresh ephemeral login role, applies a
predefined privilege set, returns a one-time connection string, and reaps the
role after its TTL. The agent connects to Postgres directly with that
ephemeral login.

This is the database analog of the OAuth broker: the same
authenticate → policy → escalate → audit spine, with an ephemeral Postgres
role in place of a minted OAuth access token.

## Non-Goals

- Engines other than PostgreSQL (MySQL, etc.) — a later spec if warranted.
- SSH / server access — a separate subsystem, different mechanism (SSH CA).
- Query proxying or row-level filtering — the broker provisions access and
  gets out of the data path; it never sees query traffic.
- Killing in-flight sessions at expiry — expiry blocks *new* logins and reaps
  the role; an open session ends naturally or via an idle timeout the operator
  configures on Postgres.

## Design Decisions (locked during brainstorming)

1. **Engine:** PostgreSQL only, end-to-end.
2. **Mechanism:** ephemeral login roles — `CREATE ROLE … LOGIN PASSWORD …
   VALID UNTIL <now+TTL>`, dropped by a reaper.
3. **Grants authored by the broker** from an operator-registered resource
   definition (not superuser hand-off, not a shared static login).
4. **Grant location:** in a **DB-resource definition**, NOT the policy file.
   The existing `PolicyEngine` is unchanged and only gates *which agent* may
   request *which resource*. Policy = who; resource = what.
5. **Admin access:** a dedicated, least-privilege `CREATEROLE` Postgres role
   whose credential lives in AgentGate's encrypted store — stored **per
   resource**, so different resources may target different servers/admin roles
   (see Multi-DB note). Never superuser.
6. **Expiry:** block new logins via `VALID UNTIL` + a **stateless background
   reaper** that DROPs expired `agentgate_%` roles; recovers dangling roles
   after a broker restart because Postgres (not broker memory) is the source
   of truth.

## Architecture

### Reused spine (unchanged)

- `broker/agent_store.py` — agent-key authentication precedes everything.
- `broker/policy_engine.py` — gates `(agent, resource-name)`; globs, time
  windows, hard-deny, hot-reload, shadow-lint all apply as-is. No schema change.
- `broker/approval.py` — escalation queue + per-agent flood cap.
- `broker/audit.py` — every decision and reap logged; no secrets.
- `broker/mcp_server.py` — HTTP MCP server with Host-header validation.
- `broker/encrypted_store.py` — base for the new resource store.

### New components

**`broker/db_resource_store.py` — `DbResourceStore(EncryptedStore)`**
Mirrors `ConnectionStore`. One entry per named resource:

| field | encrypted? | meaning |
|-------|-----------|---------|
| `name` | key | resource name (occupies the "credential" slot in policy) |
| `host`, `port`, `dbname` | clear | target DSN components |
| `admin_user` | clear | the CREATEROLE admin login |
| `admin_password` | **yes** | admin secret |
| `grants` | clear | validated list of `{verb, objects}` |
| `created_at` | clear | UTC ISO-8601 |

`store/get/delete/list_names/list_metadata` as in `ConnectionStore`;
`list_metadata` exposes name/host/dbname/grants/created_at — never the admin
password. `_SECTION = "db_resources"`.

**`broker/db_executor.py` — SQL execution seam**
```python
class DbExecutor(Protocol):
    async def run_admin(self, dsn: AdminDsn, statements: list[SqlStatement]) -> None: ...
    async def list_expired_agentgate_roles(self, dsn: AdminDsn) -> list[str]: ...
    async def drop_role(self, dsn: AdminDsn, role: str) -> None: ...
```
- `SqlStatement = (sql: str, params: tuple)` — parameters are always bound,
  never interpolated.
- Real implementation `AsyncpgExecutor` uses **asyncpg**; opens the admin
  connection, runs the mint statements in **one transaction**, closes it.
- Tests inject a `FakeExecutor` recording calls / raising on demand — the
  entire broker stays network-free in unit tests (the `oauth.post_form`
  pattern).

**`broker/db_broker.py` — orchestration**
- `mint(resource: DbResource, ttl_minutes: int) -> MintedCred` — generate
  `role = "agentgate_" + secrets.token_hex(8)`, `password =
  secrets.token_urlsafe(24)`, build the statement list
  (`CREATE ROLE … LOGIN PASSWORD $1 VALID UNTIL $2`, then one `GRANT` per
  grant entry via `quote_ident`), call `executor.run_admin` in a transaction,
  return `MintedCred(host, port, dbname, username=role, password, expires_at)`.
- `reap(resource) ` / a broker-level sweep — list expired `agentgate_%` roles,
  `drop_role` each; a failure (session still attached) is logged and retried
  next sweep.

**`Broker.request_db_credential(agent, agent_key, resource)`** in
`mcp_server.py` — authenticate → `state.read_mode` → policy decision → AUTO
grants (calls `db_broker.mint`), non-auto escalates, hard-deny/flood/timeout
deny. Same shape as `request_credential`. Audits `approved` with resource
name, generated username, expiry, and applied grants — never the password.

**Reaper loop** — `main.run` starts an `asyncio` task alongside the CLI and
MCP server: every `DB_REAP_INTERVAL_SECONDS` (default 30), for each registered
resource, run the reap sweep. Stateless; recovers after restart.

**New MCP tool** `db_credential_request(agent, agent_key, resource)` →
`{granted, host, port, dbname, username, password, expires_at, reason}`; all
secret/connection fields `null` on denial. Name is underscore-form
(MCP-spec-compliant).

**CLI** (`cli/commands.py`): `db-add <name>` (registers a resource; admin
password read from stdin/`AGENTGATE_DB_ADMIN_PASSWORD`, never argv; grants and
DSN from flags or an accompanying spec), `db-list` (metadata only), `db-remove
<name>`. Each audited as an operator action (`db-add`/`db-remove`).

### Config additions (`broker/config.py`)

| var | default | meaning |
|-----|---------|---------|
| `DB_RESOURCES_PATH` | `<AGENTGATE_HOME>/db_resources.json` | encrypted resource store |
| `DB_CRED_TTL_MINUTES` | `15` | ephemeral role lifetime (≥ 1) |
| `DB_REAP_INTERVAL_SECONDS` | `30` | reaper sweep cadence (≥ 1) |

## Data Flow

**Operator setup (once):**
1. Postgres: `CREATE ROLE agentgate_admin WITH CREATEROLE LOGIN PASSWORD '…'`,
   and grant it — `WITH GRANT OPTION` — exactly the privileges it must be able
   to delegate. Not superuser.
2. `agentgate db-add analytics-ro` — DSN + admin creds (encrypted) + grants.
3. Policy gates who: `agent: claude-*  credential: analytics-ro
   auto_approve: true`.

**Agent request:**
1. `db_credential_request(agent, agent_key, "analytics-ro")`.
2. Authenticate key → policy decision (AUTO/escalate/hard-deny/flood).
3. On grant: admin connection, single transaction — `CREATE ROLE
   agentgate_<rand> LOGIN PASSWORD $1 VALID UNTIL $2`, then the resource's
   grants. Audit `approved` (resource, username, expiry, grants).
4. Return connection fields + one-time password. Agent connects to Postgres.

**Expiry:**
5. Reaper sweep (~30s): `SELECT rolname FROM pg_roles WHERE rolname LIKE
   'agentgate\_%' AND rolvaliduntil < now()`; `DROP ROLE` each; skip+retry if a
   session still holds it. Audited. Stateless → restart-safe.

## Security

**SQL injection through identifiers.**
- Role names/passwords come from `secrets`; passwords are bound parameters,
  never inlined.
- Every grant is validated at **`db-add` time** (not request time): verb ∈
  `{SELECT, INSERT, UPDATE, DELETE}` (no `ALL`, no DDL, no role management);
  each object identifier matches `^[A-Za-z_][A-Za-z0-9_$]*$`, optionally one
  `schema.table` qualifier; emitted via `quote_ident`. A resource with an
  invalid grant never registers.

**Privilege ceiling.** The admin role is `CREATEROLE`, not superuser, and can
only delegate what it holds `WITH GRANT OPTION`. Postgres enforces this beneath
our allowlist (defense in depth). The spec's setup instructions state this
requirement explicitly.

**Fail-closed paths** (parity with the credential/OAuth paths):
- Admin unreachable / auth fail → audited `denied`, generic agent-facing reason
  (`"could not provision database credential"`), no DSN/driver detail leaked.
- Any mint statement fails → whole transaction rolls back; no half-provisioned
  role; audited `denied`.
- Reaper `DROP` failure → logged, retried next sweep; loop never dies.
- Unknown resource / unauthenticated agent / flood cap / escalation timeout →
  the same structured denials as `request_credential`.

**Secret hygiene.** The generated password appears only in the single grant
response — never audited, never in an error. `admin_password` is encrypted at
rest and dropped from memory after each admin connection.

**Residual risk (stated plainly).** AgentGate holds a `CREATEROLE` credential
and authors grants; compromise of the broker or its policy/resource files is
compromise of everything those grants can reach. Inherent to the
broker-authors-grants model chosen here — the mitigations bound it, they do not
eliminate it.

**Multi-DB note.** V1 stores admin credentials per resource, so different
resources may point at different Postgres servers/admin roles naturally. There
is no single global admin credential.

## Testing

**Unit (no Postgres; injected `FakeExecutor`):**
- `DbResourceStore`: round-trip; admin password encrypted at rest and absent
  from `list_metadata`; wrong master password fails closed.
- Grant validation: allowlisted verbs pass; `DROP`/`ALL`/`GRANT … TO`/role
  management rejected; identifiers containing quote, semicolon, space, `--`,
  backtick rejected; `schema.table` accepted; rejection is at registration.
- `db_broker.mint`: exact statement sequence (`CREATE ROLE … VALID UNTIL`,
  then grants); password passed as a bound parameter, never inlined; role name
  carries `agentgate_` prefix; returned expiry matches TTL; a mid-transaction
  raise → rollback + audited denial + generic reason.
- `reap`: expired `agentgate_%` roles → `DROP` issued; a raising `DROP` is
  skipped and retried; a non-`agentgate_` role is never dropped.
- Broker pipeline (in-process, fake executor): auth failure, unknown resource,
  AUTO grant, MANUAL escalation, hard-deny, flood cap, escalation timeout —
  each with the correct audit row and no password in the log.
- MCP tool: `db_credential_request` registered, spec-compliant name, callable
  over the in-process client.

**Integration (real Postgres; `pytest.mark.skipif` when `AGENTGATE_TEST_PG_DSN`
unset):** register a resource, mint a real ephemeral role, connect with it,
confirm a granted privilege works and an ungranted one is denied, wait out a
short TTL, run the reaper, confirm the role is gone. The one test that proves
the SQL does what the fakes assume — the DB analog of the OAuth broker's HTTP
end-to-end test.

## Files

- Create: `broker/db_resource_store.py`, `broker/db_executor.py`,
  `broker/db_broker.py`, `tests/test_db_resource_store.py`,
  `tests/test_db_broker.py`, `tests/test_db_tool.py`,
  `tests/test_db_integration.py` (skip-gated).
- Modify: `broker/config.py` (3 vars), `broker/mcp_server.py`
  (`request_db_credential` + tool registration), `broker/main.py` (reaper task
  + resource store wiring), `cli/commands.py` (`db-add`/`db-list`/`db-remove`),
  `requirements.txt`/`pyproject.toml` (asyncpg), `.env.example`, `README.md`.
- New: `.gitattributes` with `docs/ export-ignore` so `git archive` (the
  standalone-repo export path) drops internal planning docs automatically.
