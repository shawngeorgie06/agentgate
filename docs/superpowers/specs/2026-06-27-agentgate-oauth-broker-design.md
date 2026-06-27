# AgentGate OAuth Broker — Design Spec

**Date:** 2026-06-27
**Status:** Approved (design), pending implementation plan
**One-liner:** A V2 sub-project of AgentGate. Lets an operator `connect` an OAuth provider account once; afterward agents request a named connection over MCP and receive a fresh, short-lived, scoped access token — minted from a refresh token the agent never sees — governed by the existing YAML policy + escalation + audit spine.

---

## 1. Purpose & Scope

AgentGate V1 brokers static API keys: an agent asks for a credential by name and the broker hands over the secret string. The OAuth broker generalizes this to **password-restricted services that speak OAuth 2.0** (Google, GitHub, and any generic OAuth2 provider). Instead of releasing a long-lived secret, the broker holds an encrypted **refresh token** and mints **short-lived access tokens** on demand. The operator's password is never stored and never seen; agents receive only ephemeral, scoped, revocable tokens.

This is the first of three planned V2 sub-projects (OAuth, then infra/DB-SSH, then browser/SaaS). It is built first because it is the safest and most standardized, and because it establishes the reusable "mint a scoped, revocable session" pattern the later sub-projects build on.

### This sub-project's scope (build only this)

- Interactive operator onboarding via the OAuth 2.0 authorization-code flow with PKCE (browser consent once per connection).
- Built-in provider **presets for Google and GitHub** (auth/token/revoke URLs + sensible default scopes baked in), plus a **generic OAuth2** config path for any other provider.
- An encrypted **connections store** holding, per connection: provider, client ID, client secret, refresh token, granted scopes, timestamps.
- A new MCP tool `token.request` agents call to obtain an access token for a named connection.
- Reuse of the V1 pipeline: YAML policy (auto-approve / escalate / deny), AUTO/MANUAL mode, manual `[y/n]` escalation, and audit logging.
- Operator CLI commands: `connect`, `connections`, `disconnect`.
- Provider token revocation on disconnect.

### Explicitly out of scope (this sub-project — YAGNI)

Per-request scope narrowing/down-scoping, full API proxying (the broker making API calls on the agent's behalf), the browser/SaaS broker, the infra (DB/SSH) broker, team/multi-operator RBAC, automatic OAuth-app registration, and a web UI. These are deferred to later sub-projects or vNext.

---

## 2. Tech Stack

- **Language:** Python 3.11+ (consistent with V1; all modules use `from __future__ import annotations`).
- **MCP:** `fastmcp` (dotted tool names accepted verbatim).
- **HTTP:** an async HTTP client (`httpx`) for the token and revoke endpoints.
- **OAuth:** authorization-code flow with PKCE (RFC 7636); standard library is sufficient for the PKCE challenge and the temporary callback server; `httpx` for token exchange/refresh.
- **Encryption:** reuse V1's `cryptography` (AES-256-GCM) + `argon2-cffi` (Argon2id) machinery for the connections store.
- **Containerization / migration target:** unchanged from V1 — all state on env-configurable mounted-volume paths, architected for AWS ECS.

---

## 3. Architecture Constraints (non-negotiable)

Inherits all V1 constraints. The ones that bind this sub-project, plus new ones:

1. **The operator's password is never stored and never transits AgentGate.** It is entered only into the provider's own consent screen in the operator's browser. AgentGate stores only the resulting refresh token, encrypted at rest.
2. **Refresh tokens and client secrets are never returned to an agent and never logged** — not in audit entries, not in error messages. Only short-lived access tokens are released to agents.
3. **Mode is read on every request, never cached** (V1 rule). MANUAL mode escalates every `token.request` regardless of policy.
4. **Policy governs `token.request` identically to V1 credential requests** — match on agent + connection name → auto-approve / escalate / deny. An agent can never modify the policy governing its own access.
5. All store/state/log paths configurable via env; no hardcoded paths.
6. **PKCE is mandatory** on the authorization-code flow. The `state` parameter is validated on callback to prevent CSRF.

---

## 4. Components

### 4.1 OAuth module (`broker/oauth.py`) — NEW

Responsible for the protocol mechanics, isolated from storage and policy.

- **Provider presets:** a table mapping a provider key (`google`, `github`) to its authorization URL, token URL, revoke URL, and default scopes. A generic entry lets the operator supply these explicitly.
- **`begin_authorization(provider, client_id, scopes)`** → builds the authorization URL with PKCE challenge + random `state`, returns the URL plus the verifier/state to hold during the flow.
- **Temporary callback server:** binds a **fixed, env-configurable `localhost` port** (default `8765`), opens the operator's browser to the authorization URL, waits for the provider's redirect, validates `state`, captures the authorization `code`, then shuts down. The redirect URI is therefore stable (`http://localhost:8765/callback`) — this exact URI is what the operator registers in their OAuth app, so it must not be random.
- **`exchange_code(...)`** → exchanges the code (+ verifier) for `{refresh_token, access_token, expires_at, scopes}`.
- **`refresh_access_token(provider, client_id, client_secret, refresh_token)`** → returns a fresh `{access_token, expires_at, scopes}`.
- **`revoke(provider, token)`** → calls the provider's revoke endpoint.

### 4.2 Connections store (`broker/connection_store.py`) — NEW

Encrypted persistence for connections, built on V1's AES-256-GCM + Argon2id helpers (generalized from `credential_store`, or reusing its primitives).

- Record shape per connection name: `{provider, client_id, client_secret(enc), refresh_token(enc), scopes, created_at}`.
- `store(name, record)`, `get(name)`, `delete(name)`, `list_names()`.
- Client secret and refresh token are encrypted; metadata (provider, scopes, timestamps) may be stored in clear for listing.

### 4.3 Token broker core (extends `broker/mcp_server.py`)

- **`request_token(agent, connection)`**: reads mode (every call); MANUAL → escalate; else evaluate policy (agent + connection name) → auto-approve / escalate / deny. On approval, look up the connection, mint/return a fresh access token, audit the decision. On escalation timeout/denial: fail closed (no token), audit `decision="expired"`/`"denied"`.
- **In-memory access-token cache:** keyed by connection; reused until ~60s before expiry, then re-minted via the refresh token. Cache is process-local (never persisted) and dropped on disconnect.

### 4.4 MCP tool

- **`token.request({agent, connection})`** → `{access_token, token_type, expires_at, scopes}` on approval; a structured denial otherwise. Registered alongside the V1 tools.

### 4.5 Operator CLI (extends `cli/commands.py`)

- **`agentgate connect <provider> [name]`** — runs the interactive flow; `name` defaults to the provider key. Reads client ID/secret from env or config (never argv).
- **`agentgate connections`** — lists connection names, providers, scopes, and created-at (never secrets).
- **`agentgate disconnect <name>`** — revokes at the provider, deletes the encrypted record, drops the cache entry.

---

## 5. Data Flow

**Onboarding (`connect`):**
```
operator → agentgate connect google work
  → broker builds auth URL (PKCE + state), starts localhost callback server, opens browser
  → operator consents in browser (password entered ONLY at provider)
  → provider redirects to http://localhost:8765/callback?code=…&state=…
  → broker validates state, exchanges code → refresh token
  → encrypt + store connection "work"; shut down callback server
```

**Agent request (`token.request`):**
```
agent → token.request(agent="claude-code", connection="work")
  → read mode → (MANUAL: escalate) | (AUTO: policy.evaluate)
  → auto-approve → mint access token (cache or refresh) → return {access_token, expires_at, scopes}
  → escalate → operator [y/n] (fail closed on timeout) 
  → deny → structured denial
  → audit every outcome (connection, decision, mode, expiry, scopes — never tokens)
```

**Revocation (`disconnect`):**
```
operator → agentgate disconnect work
  → provider revoke endpoint → delete encrypted record → drop cache
```

---

## 6. Policy & Audit

- **Policy:** reuse the V1 YAML engine unchanged. A connection name occupies the same slot a credential name does today (agent + resource → decision). First-match, wildcards, time windows all apply as-is.
- **Audit:** one entry per `token.request` outcome with fields `{agent, connection, policy_matched, decision, mode, token_expiry, scopes}`. Decisions extend the V1 set (`approved`/`denied`/`escalated`/`expired`). **No access token, refresh token, client secret, or authorization code ever appears in the log.**

---

## 7. Security Properties (the point)

| Secret | Where it lives | Ever seen by agent? | Ever logged? |
|---|---|---|---|
| Operator password | Provider's consent screen only | No | No |
| Refresh token | Encrypted in connections store | No | No |
| Client secret | Encrypted in connections store | No | No |
| Access token | Minted on demand, cached in memory | **Yes** (ephemeral, scoped) | No (only its expiry/scopes) |

Revocation is real: `disconnect` calls the provider's revoke endpoint and deletes the refresh token, so no new tokens can be minted and outstanding ones are invalidated where the provider supports it.

---

## 8. Testing Strategy

- **OAuth module:** unit-test PKCE generation, auth-URL construction, `state` validation (reject mismatched state), and token exchange/refresh against a mocked token endpoint. No real network calls in tests.
- **Connections store:** round-trip store/get/delete; verify client secret and refresh token are not present in plaintext on disk; verify metadata listing exposes no secrets.
- **Token broker core:** auto-approve returns a token; MANUAL escalates; denial/timeout fails closed with the correct audit decision; cache reuse vs. re-mint near expiry; audit entries never contain token material.
- **CLI:** `connections` lists without secrets; `disconnect` removes the record and calls revoke (mocked).
- **Reuse:** existing V1 policy/audit/state/escalation tests continue to pass unchanged.

---

## 9. Build Order (sub-project, high level)

1. OAuth module (PKCE, auth URL, presets) — pure, mockable.
2. Connections store (encrypted persistence).
3. Token exchange + refresh wired to a mocked endpoint.
4. Token broker core (`request_token`) reusing policy/escalation/audit.
5. `token.request` MCP tool.
6. CLI `connect` (interactive callback flow), `connections`, `disconnect`.
7. Provider revocation on disconnect.
8. Docs (README section, env var reference) + whole-branch review.

(The detailed task-by-task plan is produced separately via the writing-plans skill.)
