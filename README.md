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

AgentGate exposes 5 MCP tools for agent integration:

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

All credential requests are logged to `logs/audit.log`. Each entry includes:
- Timestamp (ISO 8601)
- Agent name
- Credential name
- Decision (AUTO/MANUAL/DENIED)
- Reason (policy match, time-window rejection, operator decision)
- Request signature (no credential value)

Example:
```
{"timestamp": "2026-06-24T14:32:05Z", "agent": "claude-code", "credential": "anthropic-api-key", "decision": "AUTO", "policy": "claude-code-anthropic", "reason": "auto_approve within time window [09:00-23:00]"}
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
