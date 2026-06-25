# AgentGate — Design Spec

**Date:** 2026-06-24
**Status:** Approved (design), pending implementation plan
**One-liner:** Open-source credential broker for AI agents — IAM for agents. Agents request credentials over MCP; access is governed by YAML policies; everything is audited; anything outside policy escalates to a human for manual approval.

---

## 1. Purpose & Scope

AI agents (Claude Code, Codex, Cursor, etc.) connect to AgentGate via MCP and request credentials by name. AgentGate evaluates each request against operator-defined YAML policies. A matching auto-approve policy grants a scoped, time-limited token automatically; otherwise the request escalates to the operator for manual approval via an interactive CLI. Every request, approval, and denial is logged to an audit log.

### V1 scope (build only this)

- API keys only (no OAuth, no username/password).
- YAML policy engine.
- Two-tier approval model: auto via policy, manual escalation otherwise.
- Runtime mode toggle (AUTO / MANUAL) writing to a mounted state file.
- MCP server agents talk to via `fastmcp`.
- Audit logging to a mounted log file.
- Foreground interactive async CLI.
- Fully containerized via Docker Compose with mounted volumes for state, policies, logs, and the credential store.

### Explicitly out of scope (V1)

OAuth flows, username/password credentials, multi-operator approval, web UI, remote/distributed deployment beyond single-node Compose.

---

## 2. Tech Stack

- **Language:** Python 3.11+
- **MCP:** `fastmcp`
- **Encryption:** `cryptography` (AES-256-GCM) + `argon2-cffi` (Argon2id key derivation)
- **Containerization:** Docker Compose with mounted volumes
- **Future migration target:** AWS ECS. Architect for this from day one — state, logs, policies, and the credential store all live on mounted volumes addressed by env-configurable paths, never in container memory or the container's own filesystem.

---

## 3. Architecture Constraints (non-negotiable)

1. Mode state always lives in `state/mode.json`, never cached in memory. Read on every request.
2. Credentials are never logged in plaintext anywhere, including audit logs and error messages.
3. Policy modification always requires human confirmation, regardless of mode or any policy. An agent must never be able to modify the policies governing its own access.
4. All volume paths are configurable via `.env` so they can be swapped for ECS task definitions later.
5. No hardcoded paths anywhere in application code.

---

## 4. Project Structure

```
agentgate/
├── docker-compose.yml
├── .env.example
├── README.md
├── policies/
│   └── policies.yaml          # mounted volume
├── state/
│   └── mode.json              # mounted volume
├── logs/
│   └── audit.log              # mounted volume
├── data/
│   └── credentials.json       # mounted volume (encrypted store)
├── broker/
│   ├── __init__.py
│   ├── main.py
│   ├── mcp_server.py
│   ├── policy_engine.py
│   ├── credential_store.py
│   ├── approval.py
│   ├── audit.py
│   └── state.py
├── cli/
│   ├── __init__.py
│   └── commands.py
└── tests/
    └── test_policy_engine.py
```

`policies/`, `state/`, `logs/`, and `data/` are Docker mounted volumes. Application code only ever reaches them through env-configured paths.

---

## 5. Components

### 5.1 credential_store.py (build first)

Encrypted at-rest storage for API keys.

- **Encryption:** AES-256-GCM. Per-credential random 96-bit nonce.
- **Key derivation:** Argon2id via `argon2.low_level.hash_secret_raw`, 32-byte output. A random 16-byte salt is generated on first init and persisted in the store file (salt is not secret; it only needs to survive restarts).
- **Master password source:** `AGENTGATE_MASTER_PASSWORD` env var; if unset, fall back to an interactive `getpass` prompt at startup.
- **File shape:**

  ```json
  {
    "salt": "<base64>",
    "credentials": {
      "anthropic-api-key": { "nonce": "<base64>", "ciphertext": "<base64>" }
    }
  }
  ```

- **API:** `store(name, value)`, `retrieve(name) -> str`, `delete(name)`.
- **Safety:** never return, log, or include plaintext credential values in logs or error messages. Errors reference credential *names* only.

### 5.2 policy_engine.py + tests/test_policy_engine.py (build second, TDD)

- Loads and validates `policies.yaml` against the schema on startup; rejects malformed files with a clear, specific error.
- **Matching:** first match wins, evaluated top to bottom. Agent and credential names match by exact string or `*` wildcard.
- **Time windows:** optional `time_window` with `start`/`end` (`HH:MM`, local time). Supports windows that wrap past midnight (e.g. `22:00`–`06:00`).
- **Fallthrough:** a `default-deny` policy (`agent: "*"`, `credential: "*"`, `auto_approve: false`, `escalate: true`) catches anything unmatched.
- **Result:** a policy match produces a decision — `auto_approve` → grant; otherwise escalate.

**Policy YAML schema:**

```yaml
policies:
  - name: claude-code-anthropic
    agent: claude-code
    credential: anthropic-api-key
    access: read
    time_window:
      start: "09:00"
      end: "23:00"
    auto_approve: true

  - name: default-deny
    agent: "*"
    credential: "*"
    auto_approve: false
    escalate: true
```

### 5.3 state.py (build third)

- Reads `mode.json` on every single request; never caches.
- Writes mode changes **atomically** (write temp file, `os.replace`) so a partially-written file is never read.
- **File shape:**

  ```json
  { "mode": "auto", "updated_at": "2026-06-24T22:00:00", "updated_by": "cli" }
  ```

- `mode` is `"auto"` or `"manual"`.

### 5.4 audit.py (build fourth)

- Appends one JSON object per line to `audit.log`.
- **Entry shape:**

  ```json
  {
    "timestamp": "2026-06-24T22:14:00",
    "agent": "claude-code",
    "credential_requested": "anthropic-api-key",
    "policy_matched": "claude-code-anthropic",
    "decision": "approved",
    "mode": "auto",
    "token_expiry": "2026-06-24T23:14:00"
  }
  ```

- Never logs credential values or issued tokens. `decision` is one of `approved` / `denied` / `escalated`.

### 5.5 mcp_server.py (build fifth)

MCP interface via `fastmcp`. Tools exposed to agents:

- `credential.request` — request a named credential. Runs policy evaluation → auto-grant or escalate.
- `policy.list` — list current policies.
- `policy.validate` — validate the policy file without applying it.
- `policy.add` — add a policy. **Always escalates to human confirmation, hard-coded, not overridable by mode or policy.**
- `broker.status` — current mode, uptime, request counts (total / escalated).

### 5.6 approval.py (build sixth)

- Escalation and manual-approval logic.
- On grant: issue an opaque token (`secrets.token_urlsafe`) with a configurable TTL (default 60 min). Compute `token_expiry`. Record the decision via audit. Return the credential value to the requesting agent (over MCP only — never logged).
- On escalation: enqueue a pending request for the CLI to present `[y/n]`; resolve when the operator answers.
- MANUAL mode: every credential request escalates regardless of policy.

### 5.7 main.py (build seventh)

- Ties everything together and runs the async CLI.
- Displays current mode, loaded policy count, and request stats.
- Background async task watches stdin: `s` toggles AUTO/MANUAL (writes `mode.json` immediately) and `[y/n]` answers pending approvals inline.
- MCP server and CLI input loop run concurrently; input never blocks the whole process.
- Example output:

  ```
  [AgentGate] running in AUTO mode | policies: 3 | requests: 12 | escalated: 1
  [AgentGate] >> s
  [AgentGate] switched to MANUAL mode
  [AgentGate] pending approval: claude-code requesting anthropic-api-key [y/n]:
  ```

### 5.8 cli/commands.py (build eighth)

- Standalone CLI commands for operators (outside the running broker): e.g. store/delete a credential, validate policies, print status. Uses the same env-configured paths.

### 5.9 docker-compose.yml (build ninth)

- Containerizes the broker with `policies/`, `state/`, `logs/`, and `data/` as mounted volumes.
- All paths injected via environment from `.env`.
- `AGENTGATE_MASTER_PASSWORD` supplied as an environment secret (maps cleanly to an ECS secret later).

---

## 6. Configuration (.env)

All configurable via env / `.env` — no hardcoded paths:

- `POLICIES_PATH` (default `./policies/policies.yaml`)
- `STATE_PATH` (default `./state/mode.json`)
- `LOGS_PATH` (default `./logs/audit.log`)
- `CREDENTIALS_PATH` (default `./data/credentials.json`)
- `AGENTGATE_MASTER_PASSWORD` (no default; prompts if unset)
- `TOKEN_TTL_MINUTES` (default `60`)

---

## 7. Request Flow

```
agent --MCP--> credential.request(name)
                     │
            read mode.json (every request)
                     │
        ┌── MANUAL ──┴── AUTO ──┐
        │                       │
   escalate to CLI       policy_engine.evaluate(agent, name, now)
        │                       │
        │            ┌ auto_approve ┐ ┌ escalate ┐
   [y/n] prompt      │              │ │          │
        │         issue token   escalate to CLY  │
        │              │              │           │
        └──────────────┴── audit ─────┴───────────┘
                     │
        approved → return credential value (MCP only)
        denied   → return denial
```

Policy-mutating tools (`policy.add`) bypass this flow and always route straight to human confirmation.

---

## 8. Build Order (do not skip ahead)

1. `credential_store.py` — encrypted storage.
2. `policy_engine.py` + `test_policy_engine.py` — load, validate, match (TDD).
3. `state.py` — mode file read/write.
4. `audit.py` — event logging.
5. `mcp_server.py` — MCP interface (fastmcp).
6. `approval.py` — escalation & manual approval.
7. `main.py` — wires everything, runs the CLI.
8. `cli/commands.py` — standalone operator commands.
9. `docker-compose.yml` — containerize with mounted volumes.

After `credential_store.py` is built and working, confirm with the operator before continuing.

---

## 9. Testing

- `test_policy_engine.py` (TDD, written before policy_engine implementation): exact match, wildcard match, time-window match including midnight-wrap, malformed-YAML rejection, and `default-deny` fallthrough.
- Further component tests added as each module lands (credential round-trip, atomic state writes, audit entry shape, `policy.add` always-escalates invariant).
