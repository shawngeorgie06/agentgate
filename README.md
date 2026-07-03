# AgentGate

AgentGate is a credential broker and approval engine for AI agents — IAM for agents. Agents authenticate with a registered key, request named credentials or OAuth tokens over MCP, and get them only if a YAML policy (or the human operator) says yes. Every decision is written to an append-only audit log.

## V1 Scope

- **Agent Authentication**: agents prove identity with a high-entropy key issued at registration — a name alone grants nothing
- **Credential Storage**: Argon2id key derivation + AES-256-GCM encryption at rest (one salt per store, a fresh nonce per value), store files written owner-only (0600)
- **Policy Engine**: YAML-based declarative policies with time windows, auto-approval, and hard-deny rules; file edits take effect without a restart
- **Two-Tier Approval**: automatic approval for trusted agent/credential pairs; interactive CLI escalation for others; `escalate: false` denies without paging the operator
- **OAuth Broker**: mints short-lived, scoped access tokens (Google/GitHub presets) from refresh tokens agents never see
- **Audit Logging**: append-only JSONL of every request, approval, denial, and policy change — never any secret values
- **HTTP MCP Server**: agents connect over HTTP (`/mcp`) while the terminal stays dedicated to the operator CLI
- **Runtime Mode Toggle**: switch between AUTO and MANUAL approval at runtime; mode is persisted to a file and re-read on every request
- **Docker Ready**: non-root container, Docker Compose with mounted state volumes

## Quickstart

### Local Development

**Install dependencies:**
```bash
pip install -r requirements.txt
```

**Set up environment (optional):**
```bash
cp .env.example .env
```

Without any configuration, all state lives under `~/.agentgate/` (override the base with `AGENTGATE_HOME`, or set individual `*_PATH` variables). On first start the broker creates a default policy file there that denies and escalates everything.

**Set master password:**
Edit `.env` and set `AGENTGATE_MASTER_PASSWORD`, or leave it unset to be prompted via `getpass` at startup.

> **Warning — key next to ciphertext:** putting the master password in `.env` on the same disk as the encrypted stores means anyone who can read both has everything; encryption at rest then only protects backups and copies of the store files alone. For anything beyond local development, leave `AGENTGATE_MASTER_PASSWORD` unset and enter it at the prompt.

**Register an agent:**
Every agent must be registered before it can request anything. Registration prints the agent's key **once** — configure it on the agent (e.g. in its MCP server config); AgentGate stores only an encrypted digest.
```bash
python -m cli.commands agent-add claude-code
# registered agent 'claude-code'
# agent key (shown once — configure it on the agent, it is not stored):
# 3fK9...
```

**Seed a credential:**
The credential value is prompted for interactively (hidden input), or read from piped stdin / the `AGENTGATE_CRED_VALUE` env var — never passed as a command-line argument, so it won't leak into process listings:
```bash
# interactive (prompts for the value)
python -m cli.commands cred-store anthropic-api-key

# value piped via stdin
echo "<your-api-key>" | python -m cli.commands cred-store anthropic-api-key

# or via env var
AGENTGATE_CRED_VALUE="<your-api-key>" python -m cli.commands cred-store anthropic-api-key
```

**Run the broker:**
```bash
python -m broker.main
```

The broker serves MCP over HTTP at `http://127.0.0.1:8848/mcp` (configurable via `MCP_HOST`/`MCP_PORT`) and keeps the terminal for the operator CLI: approval prompts appear here, and mode toggling happens here.

**Connect an MCP client:**
```bash
# Claude Code
claude mcp add --transport http agentgate http://127.0.0.1:8848/mcp
```
Or in a `.mcp.json` / client config:
```json
{
  "mcpServers": {
    "agentgate": { "type": "http", "url": "http://127.0.0.1:8848/mcp" }
  }
}
```

**Request credentials from agents:**
Agents call `credential_request(agent, agent_key, credential)`. The broker verifies the agent key first, then consults policies and mode to grant, deny, or escalate.

**Toggle approval mode:**
In the broker terminal, type `s` and press Enter to toggle between AUTO and MANUAL modes. The decision is persisted to `state/mode.json` and re-read on every request (never cached).

### Docker Compose

**Build and run:**
```bash
docker compose build
docker compose up
```

The container runs as a non-root user, publishes the MCP endpoint on the **host's loopback only** (`127.0.0.1:8848`), and mounts all state directories (`policies`, `state`, `logs`, `data`) from the host. Approval prompts appear on the compose foreground terminal — run `docker compose up` (not `-d`) when you expect escalations, or attach with `docker attach`.

Run CLI commands (registration, credential seeding) on the host against the same mounted `data/` directory, or via `docker compose exec agentgate python -m cli.commands ...`.

## Policy Schema

Policies are defined in `policies/policies.yaml`. Each policy specifies:

```yaml
policies:
  - name: <policy-name>
    agent: <exact name or glob pattern: "*", "claude-*", "agent-?">
    credential: <exact name or glob pattern>
    time_window:               # optional; omit for 24/7 (times are operator-local)
      start: "HH:MM"
      end: "HH:MM"
    auto_approve: true|false   # grant immediately when matched (in AUTO mode)
    escalate: true|false       # on a non-auto match: true = ask the operator,
                               # false = deny immediately without paging anyone
```

**Example:**
```yaml
- name: claude-code-anthropic
  agent: claude-code
  credential: anthropic-api-key
  time_window:
    start: "09:00"
    end: "23:00"
  auto_approve: true

- name: never-prod
  agent: "*"
  credential: prod-db-password
  auto_approve: false
  escalate: false          # hard deny: audited, no operator prompt

- name: default-deny
  agent: "*"
  credential: "*"
  auto_approve: false
  escalate: true
```

The first matching policy wins; policies are evaluated in order. Edits to the file are picked up automatically on the next request — an invalid edit keeps the last valid policies in effect (with a warning on the broker's stderr) rather than taking the broker down.

Because first-match-wins makes ordering a footgun, `agentgate policy-validate` (and the `policy_validate` tool) also warn about **unreachable policies** — ones fully shadowed by an earlier always-on policy.

## MCP Tools

AgentGate exposes 6 MCP tools. The three that grant or change anything require the agent's registered key; an unknown agent or wrong key gets an audited denial and never reaches a policy match or the operator.

1. **`credential_request(agent, agent_key, credential)`** — Request a stored credential. Returns `{granted: bool, value: str, reason: str}`; `value` is `null` when denied. Note: the granted value **is** the raw credential — treat the response as secret.

2. **`token_request(agent, agent_key, connection)`** — Request a short-lived OAuth access token for a named connection (see [OAuth Broker](#oauth-broker)). Returns `{granted: bool, access_token: str, token_expiry: str, scopes: [str], reason: str}`; when `granted` is `false`, `access_token`, `token_expiry`, and `scopes` are `null`. Governed by policy/escalation/audit exactly like `credential_request` (the connection name occupies the credential slot).

3. **`policy_list()`** — List all policies. Returns `{policies: [{name, agent, credential, auto_approve, escalate, ...}]}`.

4. **`policy_validate()`** — Validate the policy file without applying it. Returns `{valid: bool, errors: [str], warnings: [str]}` (warnings flag unreachable/shadowed policies).

5. **`policy_add(agent, agent_key, policy)`** — Propose a new policy. **Always escalates to the CLI operator, regardless of mode**, and the operator sees the full policy body — not just its name. An approved policy is inserted **above a trailing catch-all default-deny but never ahead of existing specific policies**, so a proposed policy cannot steal precedence. Every outcome (escalated/approved/denied/expired) is audited.

6. **`broker_status()`** — Current broker status. Returns `{mode: str, policies: int, requests: int, escalated: int, uptime_seconds: int}`.

## Approval Modes

AgentGate runs in two modes:

- **AUTO**: policies with `auto_approve: true` grant immediately; non-auto matches escalate (or hard-deny if `escalate: false`).
- **MANUAL**: every authenticated request escalates to the CLI operator, even when a policy would auto-approve.

Toggle by typing `s` + Enter in the broker terminal. The mode is persisted to `state/mode.json` and re-read on every request. A missing mode file defaults to AUTO (fresh install); a corrupt or unreadable one **fails closed to MANUAL**.

## Agent Registration

Agent identity is authenticated, not asserted. `agent-add` issues a random 256-bit key and stores only an encrypted SHA-256 digest — the key is never on disk and never in the audit log. Verification is constant-time.

```bash
agentgate agent-add claude-code     # prints the key once
agentgate agent-list                # names only
agentgate agent-remove claude-code  # revoke immediately (broker picks it up without restart)
```

## OAuth Broker

Beyond static API keys, AgentGate can broker **OAuth 2.0 access** to providers like Google and GitHub. You connect a provider account once; afterward an agent asks for that connection by name and receives a **fresh, short-lived, scoped access token** minted from a refresh token it never sees. Your password is never stored — only the refresh token, encrypted at rest — and you can revoke a connection at any time.

### How it works

- The broker holds an encrypted **refresh token** per connection (never released to agents).
- On `token_request`, the broker mints a short-lived **access token** (caching it in memory until shortly before expiry) and returns only that token plus its expiry and scopes.
- Access is governed by the same agent authentication, YAML policy, AUTO/MANUAL mode, escalation, and audit pipeline as `credential_request`.

### One-time provider setup

Interactive OAuth requires your own OAuth app (an open-source, self-hosted broker can't ship shared client secrets):

1. Register an OAuth app in the provider's developer console (Google Cloud Console / GitHub Developer Settings).
2. Set its authorized redirect URI to **`http://localhost:8765/callback`** (or your configured `OAUTH_REDIRECT_PORT`). This must match exactly.
3. Note the **client ID** and **client secret**.

Built-in presets exist for **Google** and **GitHub** (their auth/token/revoke URLs and default scopes are baked in).

### Operator commands

`connect` needs a browser and the localhost callback, so run it **on the host** (not inside the container) against the same mounted `data/` directory:

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
token_request(agent="claude-code", agent_key="<key>", connection="work")
  -> {granted: true, access_token: "...", token_expiry: "2026-06-28T15:00:00+00:00", scopes: ["openid", "email"], reason: "..."}
```

The refresh token, client secret, and authorization code are **never** returned to an agent and **never** written to the audit log — only the access token's expiry and granted scopes are recorded.

## Audit Log

All decisions are logged to `logs/audit.log`, one JSON object per line (append-only; the file is written owner-only). Each entry includes:
- `timestamp` — ISO-8601, UTC
- `agent` — requesting agent name
- `credential_requested` — credential/connection name, or `policy.add:<name>` for policy proposals (never any value)
- `policy_matched` — the policy that decided the request; `unauthenticated` when the agent key check failed
- `decision` — one of `approved`, `denied`, `escalated`, `expired` (`expired` = escalated request that timed out waiting for the operator and was auto-denied)
- `mode` — the broker mode at decision time (`auto` or `manual`)
- `token_expiry` — expiry of the OAuth access token, or `null` when none was issued
- `scopes` — granted OAuth scopes (token grants only)

Operator mutations are audited too — seeding/deleting credentials, registering/revoking agents, adding/removing OAuth connections, and mode toggles each write an `{actor: "operator", action, subject}` row (names only, never values or keys), so "when was this credential added and by whom" is answerable.

Credential values, OAuth tokens, and agent keys are never written to the audit log. The log is plain append-only JSONL — it is **not** cryptographically tamper-evident; protect it with filesystem permissions and ship it somewhere append-only if you need stronger guarantees.

Examples:
```
{"timestamp": "2026-06-24T14:32:05+00:00", "agent": "claude-code", "credential_requested": "anthropic-api-key", "policy_matched": "claude-code-anthropic", "decision": "approved", "mode": "auto", "token_expiry": null}
{"timestamp": "2026-06-24T14:30:11+00:00", "actor": "operator", "action": "cred-store", "subject": "anthropic-api-key"}
```

## Failure Behavior

AgentGate fails closed:

- unknown agent or wrong key → audited denial, no escalation
- unknown credential/connection → audited denial
- store decryption failure (wrong password, tampered file) → audited denial with a generic reason
- OAuth refresh failure → audited denial, no raw provider error reaches the agent
- corrupt mode file → MANUAL mode (everything escalates)
- invalid policy-file edit → last valid policies stay in effect (warning on stderr)
- escalation timeout → audited `expired`, denied
- more than `ESCALATION_MAX_PENDING` (default 3) unresolved escalations from one agent → further requests denied immediately (approval-fatigue defense; other agents unaffected)
- HTTP request with a non-allowlisted `Host` header → rejected with 400 (DNS-rebinding defense; extend the allowlist via `MCP_ALLOWED_HOSTS` if you deliberately serve beyond loopback)

## ECS Migration

All runtime state is stored in environment-configured mounted volumes:

- `POLICIES_PATH` → `policies/policies.yaml` (policy definitions)
- `STATE_PATH` → `state/mode.json` (current approval mode)
- `LOGS_PATH` → `logs/audit.log` (audit trail)
- `CREDENTIALS_PATH` → `data/credentials.json` (encrypted credentials)
- `CONNECTIONS_PATH` → `data/connections.json` (encrypted OAuth connections)
- `AGENTS_PATH` → `data/agents.json` (encrypted agent-key digests)

In ECS, mount these as external volumes and inject the paths via environment variables. Note: AgentGate is currently a **single-instance** design — the approval queue, OAuth token cache, and request counters live in process memory, so horizontal scaling requires the V2 shared-state work (DynamoDB/S3).

## Credential Storage

Secrets are encrypted at rest using:

- **Key Derivation**: Argon2id (RFC 9106) from the operator's master password, one random salt per store file
- **Encryption**: AES-256-GCM with a fresh random nonce per value
- **Permissions**: store files are written `0600` (owner-only)

Store files are re-read on every access, so CLI writes (new credentials, revoked agents) take effect on a running broker without a restart.

## Escalation Timeout

Set `ESCALATION_TIMEOUT_SECONDS` in `.env` to limit how long the broker waits for operator approval before failing closed. When the timeout elapses with no operator response, the request is denied immediately and audited as `decision="expired"`. A value of `0` (the default) disables the timeout and waits forever — suitable for interactive use. Set a positive integer (e.g. `30`) for headless or unattended deployments where a hung approval queue should not block agents indefinitely.

`ESCALATION_MAX_PENDING` (default `3`) caps how many unresolved escalations a single agent may stack; beyond it, that agent's requests are denied immediately with an audit row while other agents remain unaffected. This bounds both operator prompt-fatigue and per-agent memory growth.

## Architecture

**Broker** (`broker/main.py`):
- FastMCP server (HTTP transport at `/mcp`; the terminal belongs to the operator CLI)
- Agent registry (encrypted key digests)
- Credential + connection stores (encrypted JSON, re-read per access)
- Policy engine (YAML parser + time-window evaluator, hot-reloaded on file change)
- Approval queue (pending requests awaiting operator decision)
- Audit logger (append-only JSONL)

**CLI** (`cli/commands.py`):
- Agent registration (`agent-add`, `agent-remove`, `agent-list`)
- Credential management (`cred-store`, `cred-delete`, `cred-list`)
- OAuth connections (`connect`, `connections`, `disconnect`)
- Policy administration (`policy-validate`)
- Broker status (`status`)

**Config** (`broker/config.py`):
- Environment variable parsing and validation
- Master password resolution (env or `getpass`)

## Testing

Run the full test suite:
```bash
pip install -e .[dev]
python -m pytest -v
```

Expected: 125 tests covering encryption round-trips, agent authentication, policy evaluation (globs, time windows, hard deny, hot reload, shadowing lint), two-tier approval with flood caps, fail-closed error paths, secret-free audit output, and an end-to-end MCP call over the real HTTP transport including Host-header rejection.
