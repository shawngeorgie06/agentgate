# AgentGate

AgentGate is a prototype credential broker and approval engine for AI agents. It enforces time-based policy gates on API key access, provides two-tier approval workflows (AUTO for trusted policies, MANUAL for escalations), and audits credential decisions with append-only file logging.

## V1 Scope

- **Credential Storage**: Argon2id + AES-256-GCM encrypted credential storage with per-credential salts and nonces
- **Policy Engine**: YAML-based declarative policies with time windows and auto-approval rules
- **Two-Tier Approval**: Automatic approval for trusted agent/credential pairs; escalation to CLI operator for others
- **Audit Logging**: Append-only JSON audit trail (no credential values logged)
- **FastMCP Server**: Built-in Model Context Protocol server exposing credential, policy, and Gmail MCP tools for agent integration
- **Runtime Mode Toggle**: Interactive CLI toggle between AUTO and MANUAL approval modes (state persisted to JSON)
- **Async CLI**: Command-line interface for credential management and policy administration
- **Docker Ready**: Docker Compose configuration with mounted state volumes for ECS migration

## Quickstart

### Local Development

**Install dependencies:**
```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r requirements.txt
source .venv/bin/activate
```

**Set up environment:**
```bash
cp .env.example .env
```

**Set master password:**
Set `AGENTGATE_MASTER_PASSWORD` in your shell environment (or the interactive broker will prompt via `getpass`). The application does not automatically load `.env`; Docker Compose loads it via `env_file`.

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

The broker starts a FastMCP server over stdin/stdout. An MCP client launches this command and owns those streams. Operator approvals use `/dev/tty`, the controlling terminal, and startup diagnostics go to stderr. Interactive approvals on macOS/Linux require the server process to retain a controlling terminal. Clients that detach their subprocesses (including FastMCP’s stdio client), and desktop clients without a terminal, use headless mode even if the client was launched from a shell. The terminal shows requests as they arrive; answer `y` or `n`, press `s` then Enter to toggle modes, or `q` then Enter to stop.

For a safe standalone walkthrough with temporary dummy credentials:
```bash
python -m examples.demo
```
Approve the first request with `y`, then deny the second with `n`. This demo exercises the MCP tools in process; it does not modify your real credentials, policies, or audit log.

Without a controlling terminal, the broker requires `AGENTGATE_MASTER_PASSWORD` and a positive `ESCALATION_TIMEOUT_SECONDS`. Automatic policies still work; requests needing an operator time out and are denied.

**Request credentials from agents:**
Agents connect to AgentGate via MCP and call `credential.request(agent, credential)`. The broker consults policies and audit state to approve or escalate the request.

**Toggle approval mode:**
Once the CLI is running, press `s` then Enter to toggle between AUTO and MANUAL approval modes. The decision is persisted to `state/mode.json` and read on every request (never cached).

### Docker Compose

**Build and run:**
```bash
docker compose build
docker compose up
```

The container mounts all state directories (`policies`, `state`, `logs`, `data`) from the host, making it suitable for ECS task definitions that mount external state volumes.

## Gmail

Connect Gmail once using Google OAuth, then let local agents search, read, and create drafts. Every email send requires operator approval. Tokens stay inside the encrypted broker store. Agents can use `.venv/bin/python -m cli.agent` for JSON commands (`status`, `search`, `read`, `draft`, `send-draft`) through the authenticated local broker. See the [Gmail setup guide](docs/gmail.md) for Google setup, policies, tools, and current terminal requirements.

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

AgentGate exposes these core MCP tools for agent integration:

1. **`credential.request`** — Request a credential by agent name and credential name. Returns `{granted: bool, token: str, token_expiry: int, value: str, reason: str}`.

2. **`policy.list`** — List all policies and their current status. Returns `{policies: [{name, agent, credential, auto_approve, escalate, ...}]}`.

3. **`policy.validate`** — Validate the policy file without applying it. Returns `{valid: bool, errors: [str]}`.

4. **`policy.add`** — Add a new policy. **Always escalates to CLI operator for approval, regardless of mode.** Once approved, the policy is persisted to `policies/policies.yaml`.

5. **`broker.status`** — Get current broker status: mode, policy count, request/escalation counts, and uptime. Returns `{mode: str, policies: int, requests: int, escalated: int, uptime_seconds: int}`.

## Approval Modes

AgentGate runs in two modes:

- **AUTO**: Policies with `auto_approve: true` grant credentials immediately. Policies with `auto_approve: false` still escalate to the operator.
- **MANUAL**: All requests (even auto-approval policies) escalate to the CLI operator for interactive approval or denial.

Toggle modes by pressing `s` while the CLI is running. The mode is persisted to `state/mode.json`.

## Audit Log

All credential decisions are logged to `logs/audit.log`, one JSON object per line. Each entry includes:
- `timestamp` — ISO-8601, local time
- `agent` — requesting agent name
- `credential_requested` — credential name (never the value)
- `policy_matched` — the policy that decided the request
- `decision` — one of `approved`, `denied`, `escalated`, `expired`, `completed`, `failed` (`completed` and `failed` record Gmail operation outcomes; `expired` = escalated request that timed out waiting for the operator and was auto-denied)
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

In ECS, mount these volumes as external storage (e.g., EFS or S3-backed volumes) and inject the paths via environment variables. AgentGate will read and write state atomically, but atomic replacement alone does not prevent concurrent writers from losing updates. Multi-instance use requires additional locking or transactional storage.

## Credential Storage

Credentials are encrypted at rest using:

- **Key Derivation**: Argon2id (RFC 9106) with user-configured master password
- **Encryption**: AES-256-GCM with per-credential salts and nonces
- **Audit**: Credential decisions logged without credential values

The broker accepts agent names supplied by MCP callers; it does not authenticate those identities. Use local trusted clients only. Credential values are omitted from the audit log but are returned to approved callers.

## Token TTL

Granted credentials include a `token_expiry` timestamp (configurable via `TOKEN_TTL_MINUTES` in `.env`, default 60 minutes). This expiry is metadata only: the broker returns the underlying API key and does not enforce token redemption or revoke the key at expiry.

## Escalation Timeout

Set `ESCALATION_TIMEOUT_SECONDS` in `.env` to limit how long the broker waits for operator approval before failing closed. When the timeout elapses with no operator response, the request is denied immediately and audited as `decision="expired"`. A value of `0` (the default) disables the timeout and waits forever — suitable for interactive use. Set a positive integer (e.g. `30`) for headless or unattended deployments where a hung approval queue should not block agents indefinitely. Note: while the timeout is disabled by default, pending approvals with no operator answer accumulate in memory—headless deployments should set a positive timeout to prevent unbounded memory growth.

## Architecture

**Broker** (`broker/main.py`):
- FastMCP server (stdin/stdout transport)
- Credential store (encrypted JSON)
- Policy engine (YAML parser + time-window evaluator)
- Approval queue (pending requests awaiting operator decision)
- Audit logger (append-only file log)

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

Tests cover:
- Credential encryption/decryption
- Policy evaluation and time-window matching
- Two-tier approval workflows
- Audit logging (values never logged)
- MCP tool interface
