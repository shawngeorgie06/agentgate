# AgentGate

AgentGate is a production-grade credential broker and approval engine for AI agents. It enforces time-based policy gates on API key access, provides two-tier approval workflows (AUTO for trusted policies, MANUAL for escalations), and audits all credential requests with immutable logging.

## V1 Scope

- **Credential Storage**: Argon2id + AES-256-GCM encrypted credential storage with per-credential salts and nonces
- **Policy Engine**: YAML-based declarative policies with time windows and auto-approval rules
- **Two-Tier Approval**: Automatic approval for trusted agent/credential pairs; escalation to CLI operator for others
- **Audit Logging**: Immutable audit trail with request signatures (no credential values logged)
- **FastMCP Server**: Built-in Model Context Protocol server exposing 5 standard MCP tools for agent integration
- **Runtime Mode Toggle**: Interactive CLI toggle between AUTO and MANUAL approval modes (state persisted to JSON)
- **Async CLI**: Command-line interface for credential management and policy administration
- **Docker Ready**: Docker Compose configuration with mounted state volumes for ECS migration

## Quickstart

### Local Development

**Install dependencies:**
```bash
pip install -r requirements.txt
```

**Set up environment:**
```bash
cp .env.example .env
```

**Set master password:**
Edit `.env` and set `AGENTGATE_MASTER_PASSWORD` to a secure value (or it will prompt via `getpass` on CLI startup).

**Seed a credential:**
The credential value is read from stdin or the `AGENTGATE_CRED_VALUE` env var (never passed as a command-line argument, so it won't leak into process listings):
```bash
# value piped via stdin
echo "<your-api-key>" | python -m cli.commands cred-store anthropic-api-key

# or via env var
AGENTGATE_CRED_VALUE="<your-api-key>" python -m cli.commands cred-store anthropic-api-key
```

**Run the broker:**
```bash
python -m broker.main
```

The broker starts a FastMCP server (stdin/stdout transport) and begins listening for credential requests via `credential.request` RPC calls.

**Request credentials from agents:**
Agents connect to AgentGate via MCP and call `credential.request(agent, credential)`. The broker consults policies and audit state to approve or escalate the request.

**Toggle approval mode:**
Once the CLI is running, press `s` to toggle between AUTO and MANUAL approval modes. The decision is persisted to `state/mode.json` and read on every request (never cached).

### Docker Compose

**Build and run:**
```bash
docker compose build
docker compose up
```

The container mounts all state directories (`policies`, `state`, `logs`, `data`) from the host, making it suitable for ECS task definitions that mount external state volumes.

## Policy Schema

Policies are defined in `policies/policies.yaml`. Each policy specifies:

```yaml
policies:
  - name: <policy-name>
    agent: <agent-name or "*" for wildcard>
    credential: <credential-name or "*" for wildcard>
    access: read|write         # access level (for future expansion)
    time_window:               # optional; omit for 24/7
      start: "HH:MM"
      end: "HH:MM"
    auto_approve: true|false   # auto-approve if time window matches
    escalate: true             # if true, failed auto-approval escalates to CLI operator
```

**Example:**
```yaml
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

The first matching policy wins. Policies are evaluated in order.

## MCP Tools

AgentGate exposes 6 MCP tools for agent integration:

1. **`credential.request`** — Request a credential by agent name and credential name. Returns `{granted: bool, token: str, token_expiry: int, value: str, reason: str}`.

2. **`token.request`** — Request a short-lived OAuth access token for a named connection (see [OAuth Broker](#oauth-broker)). Returns `{granted: bool, access_token: str, token_expiry: str, scopes: [str], reason: str}`. Governed by policy/escalation/audit exactly like `credential.request` (match on agent + connection name).

3. **`policy.list`** — List all policies and their current status. Returns `{policies: [{name, agent, credential, auto_approve, escalate, ...}]}`.

4. **`policy.validate`** — Validate the policy file without applying it. Returns `{valid: bool, errors: [str]}`.

5. **`policy.add`** — Add a new policy. **Always escalates to CLI operator for approval, regardless of mode.** Once approved, the policy is persisted to `policies/policies.yaml`.

6. **`broker.status`** — Get current broker status: mode, policy count, request/escalation counts, and uptime. Returns `{mode: str, policies: int, requests: int, escalated: int, uptime_seconds: int}`.

## Approval Modes

AgentGate runs in two modes:

- **AUTO**: Policies with `auto_approve: true` grant credentials immediately. Policies with `auto_approve: false` still escalate to the operator.
- **MANUAL**: All requests (even auto-approval policies) escalate to the CLI operator for interactive approval or denial.

Toggle modes by pressing `s` while the CLI is running. The mode is persisted to `state/mode.json`.

## OAuth Broker

Beyond static API keys, AgentGate can broker **OAuth 2.0 access** to providers like Google and GitHub. You connect a provider account once; afterward an agent asks for that connection by name and receives a **fresh, short-lived, scoped access token** minted from a refresh token it never sees. Your password is never stored — only the refresh token, encrypted at rest — and you can revoke a connection at any time.

### How it works

- The broker holds an encrypted **refresh token** per connection (never released to agents).
- On `token.request`, the broker mints a short-lived **access token** (caching it in memory until shortly before expiry) and returns only that token plus its expiry and scopes.
- Access is governed by the same YAML policy, AUTO/MANUAL mode, escalation, and audit pipeline as `credential.request` — the connection name occupies the same slot a credential name does.

### One-time provider setup

Interactive OAuth requires your own OAuth app (an open-source, self-hosted broker can't ship shared client secrets):

1. Register an OAuth app in the provider's developer console (Google Cloud Console / GitHub Developer Settings).
2. Set its authorized redirect URI to **`http://localhost:8765/callback`** (or your configured `OAUTH_REDIRECT_PORT`). This must match exactly.
3. Note the **client ID** and **client secret**.

Built-in presets exist for **Google** and **GitHub** (their auth/token/revoke URLs and default scopes are baked in).

### Operator commands

```bash
# Provide the client ID/secret for the provider you're connecting (read from the
# environment at connect time — never passed as a command-line argument):
export AGENTGATE_OAUTH_CLIENT_ID=<your-client-id>
export AGENTGATE_OAUTH_CLIENT_SECRET=<your-client-secret>

# Connect an account (opens your browser to consent once; captures + encrypts the refresh token):
agentgate connect google work        # `work` is the connection name; defaults to the provider

# List connected accounts (shows name, provider, scopes, created-at — never secrets):
agentgate connections

# Revoke at the provider and remove the local record:
agentgate disconnect work
```

> The browser consent screen is the **only** place your provider password is entered — AgentGate never sees it. `connect` opens a temporary `localhost` callback server (PKCE + `state` CSRF protection) that serves exactly the OAuth redirect, then shuts down.

### Agent usage

An agent requests a token over MCP:

```
token.request(agent="claude-code", connection="work")
  -> {granted: true, access_token: "...", token_expiry: "2026-06-28T15:00:00", scopes: ["openid", "email"], reason: "..."}
```

The refresh token, client secret, and authorization code are **never** returned to an agent and **never** written to the audit log — only the access token's expiry and granted scopes are recorded.

## Audit Log

All credential decisions are logged to `logs/audit.log`, one JSON object per line. Each entry includes:
- `timestamp` — ISO-8601, local time
- `agent` — requesting agent name
- `credential_requested` — credential name (never the value)
- `policy_matched` — the policy that decided the request
- `decision` — one of `approved`, `denied`, `escalated`, `expired` (`expired` = escalated request that timed out waiting for the operator and was auto-denied)
- `mode` — the broker mode at decision time (`auto` or `manual`)
- `token_expiry` — expiry of the issued token, or `null` when no token was issued

The credential value and the issued token are never written to the audit log.

Example:
```
{"timestamp": "2026-06-24T14:32:05", "agent": "claude-code", "credential_requested": "anthropic-api-key", "policy_matched": "claude-code-anthropic", "decision": "approved", "mode": "auto", "token_expiry": "2026-06-24T15:32:05"}
```

## ECS Migration

All runtime state is stored in environment-configured mounted volumes:

- `POLICIES_PATH` → `policies/policies.yaml` (policy definitions)
- `STATE_PATH` → `state/mode.json` (current approval mode)
- `LOGS_PATH` → `logs/audit.log` (audit trail)
- `CREDENTIALS_PATH` → `data/credentials.json` (encrypted credentials)

In ECS, mount these volumes as external storage (e.g., EFS or S3-backed volumes) and inject the paths via environment variables. AgentGate will read and write state atomically, making it safe for horizontal scaling with shared state.

## Credential Storage

Credentials are encrypted at rest using:

- **Key Derivation**: Argon2id (RFC 9106) with user-configured master password
- **Encryption**: AES-256-GCM with per-credential salts and nonces
- **Audit**: All credential requests logged without values (signatures only)

Credentials are accessed only via authenticated MCP calls and are never logged in plaintext.

## Token TTL

Granted credentials include a `token_expiry` timestamp (configurable via `TOKEN_TTL_MINUTES` in `.env`, default 60 minutes). Agents must re-request before expiry.

## Escalation Timeout

Set `ESCALATION_TIMEOUT_SECONDS` in `.env` to limit how long the broker waits for operator approval before failing closed. When the timeout elapses with no operator response, the request is denied immediately and audited as `decision="expired"`. A value of `0` (the default) disables the timeout and waits forever — suitable for interactive use. Set a positive integer (e.g. `30`) for headless or unattended deployments where a hung approval queue should not block agents indefinitely. Note: while the timeout is disabled by default, pending approvals with no operator answer accumulate in memory—headless deployments should set a positive timeout to prevent unbounded memory growth.

## Architecture

**Broker** (`broker/main.py`):
- FastMCP server (stdin/stdout transport)
- Credential store (encrypted JSON)
- Policy engine (YAML parser + time-window evaluator)
- Approval queue (pending requests awaiting operator decision)
- Audit logger (immutable append-only log)

**CLI** (`cli/commands.py`):
- Credential management (`cred-store`, `cred-delete`, `cred-list`)
- Policy administration (`policy-validate`)
- Broker status (`status`)
- Approval prompt (interactive decision queue)
- Mode toggle (`s` key)

**Config** (`broker/config.py`):
- Environment variable parsing
- Master password resolution (env or `getpass`)
- Path initialization and validation

## Testing

Run the full test suite:
```bash
python -m pytest -v
```

Expected: 41 passing tests covering:
- Credential encryption/decryption
- Policy evaluation and time-window matching
- Two-tier approval workflows
- Audit logging (values never logged)
- MCP tool interface
