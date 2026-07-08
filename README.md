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

AgentGate exposes 9 MCP tools. The six that grant or change anything require the agent's registered key; an unknown agent or wrong key gets an audited denial and never reaches a policy match or the operator.

1. **`credential_request(agent, agent_key, credential)`** — Request a stored credential. Returns `{granted: bool, value: str, reason: str}`; `value` is `null` when denied. Note: the granted value **is** the raw credential — treat the response as secret.

2. **`token_request(agent, agent_key, connection)`** — Request a short-lived OAuth access token for a named connection (see [OAuth Broker](#oauth-broker)). Returns `{granted: bool, access_token: str, token_expiry: str, scopes: [str], reason: str}`; when `granted` is `false`, `access_token`, `token_expiry`, and `scopes` are `null`. Governed by policy/escalation/audit exactly like `credential_request` (the connection name occupies the credential slot).

3. **`policy_list()`** — List all policies. Returns `{policies: [{name, agent, credential, auto_approve, escalate, ...}]}`.

4. **`policy_validate()`** — Validate the policy file without applying it. Returns `{valid: bool, errors: [str], warnings: [str]}` (warnings flag unreachable/shadowed policies).

5. **`policy_add(agent, agent_key, policy)`** — Propose a new policy. **Always escalates to the CLI operator, regardless of mode**, and the operator sees the full policy body — not just its name. An approved policy is inserted **above a trailing catch-all default-deny but never ahead of existing specific policies**, so a proposed policy cannot steal precedence. Every outcome (escalated/approved/denied/expired) is audited.

6. **`broker_status()`** — Current broker status. Returns `{mode: str, policies: int, requests: int, escalated: int, uptime_seconds: int}`.

7. **`db_credential_request(agent, agent_key, resource)`** — Request an ephemeral, scoped PostgreSQL credential for a named database resource (see [PostgreSQL Infra Broker](#postgresql-infra-broker)). Returns `{granted: bool, host: str, port: int, dbname: str, username: str, password: str, expires_at: str, reason: str}`; all fields but `granted`/`reason` are `null` when denied. Note: the granted `password` **is** a real, working database credential (short-lived, TTL-limited) — treat it as secret. Governed by policy/escalation/audit exactly like `credential_request` (the resource name occupies the credential slot).

8. **`ssh_certificate_request(agent, agent_key, resource)`** — Request an ephemeral SSH login certificate for a named server resource (see [SSH Broker](#ssh-broker)). Returns `{granted: bool, host: str, port: int, username: str, private_key: str, certificate: str, expires_at: str, reason: str}`; all fields but `granted`/`reason` are `null` when denied. Note: the granted `private_key` **is** a working (TTL-limited) SSH key — treat the response as secret. Governed by policy/escalation/audit exactly like `credential_request` (the resource name occupies the credential slot).

9. **`aws_credential_request(agent, agent_key, resource)`** — Request short-lived AWS credentials for a named role resource (see [AWS Broker](#aws-broker)). Returns `{granted: bool, access_key_id: str, secret_access_key: str, session_token: str, expiration: str, region: str, reason: str}`; all credential fields are `null` when denied. Note: the granted keys **are** working (TTL-limited) AWS credentials — treat the response as secret. Governed by policy/escalation/audit exactly like `credential_request` (the resource name occupies the credential slot).

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

## PostgreSQL Infra Broker

Beyond static API keys and OAuth tokens, AgentGate can broker **live database access**: an agent asks for a named resource and receives a brand-new, short-lived PostgreSQL role scoped to exactly the grants you registered — never a standing credential, never the admin connection itself.

### The model

- Each registered resource (`agentgate db-add`) carries its own encrypted admin DSN and a list of grants (`VERB:schema.table`, e.g. `SELECT:public.events`).
- On `db_credential_request`, the broker creates a **fresh, randomly-named role** (`agentgate_<hex>`) with a random password, applies exactly the registered grants to it, and hands the credential to the agent. Nothing is reused across requests — every grant is a brand-new role minted for that request and torn down after its TTL.
- The agent never sees the admin credential, and the minted role can only do what the resource's grants say (verbs are allowlisted to `SELECT`/`INSERT`/`UPDATE`/`DELETE`; object identifiers are validated against a safe-identifier pattern at `db-add` time, not request time).

### One-time operator setup

AgentGate needs a dedicated PostgreSQL role that can create and grant — but should not be a superuser:

```sql
CREATE ROLE agentgate_admin WITH LOGIN CREATEROLE PASSWORD '...';

-- Grant it only what it may delegate, WITH GRANT OPTION so it can pass
-- the privilege on to the ephemeral roles it mints:
GRANT SELECT ON public.events TO agentgate_admin WITH GRANT OPTION;
```

`agentgate_admin` should **not** be granted superuser or any privilege you don't want an agent to eventually receive — it can only delegate privileges it already holds `WITH GRANT OPTION`.

### Registering a resource

```bash
agentgate db-add analytics-ro --host db.internal --port 5432 --dbname analytics \
  --admin-user agentgate_admin --grant "SELECT:public.events"
```

The admin password is read from `AGENTGATE_DB_ADMIN_PASSWORD`, interactive `getpass`, or piped stdin — never a command-line argument — and stored encrypted alongside the resource. `--grant` is repeatable for multiple verb/object pairs. `agentgate db-list` shows registered resources (host/port/dbname/grants, never the admin password); `agentgate db-remove <name>` deletes one. Both `db-add` and `db-remove` are recorded as operator actions in the audit log.

### Agent usage

An agent requests a credential over MCP:

```
db_credential_request(agent="claude-code", agent_key="<key>", resource="analytics-ro")
  -> {granted: true, host: "db.internal", port: 5432, dbname: "analytics",
      username: "agentgate_3fa9...", password: "...", expires_at: "2026-07-02T10:15:00+00:00",
      reason: "auto-approved by policy 'analytics-read'"}
```

Access is governed by the same agent authentication, YAML policy, AUTO/MANUAL mode, escalation, and audit pipeline as `credential_request` — only `username` and the granted verbs/objects are audited, never the password.

### TTL and reaping

Every minted role is created with `VALID UNTIL` set to the request time plus `DB_CRED_TTL_MINUTES` (default 15). Expiry **blocks new logins** — it does not terminate sessions already open at expiry time, which end naturally when the agent disconnects. A background reaper sweeps every `DB_REAP_INTERVAL_SECONDS` (default 30), finds roles in the `agentgate_` namespace whose `VALID UNTIL` has passed, and drops them; a role still holding an open session is retried on the next sweep rather than forcibly disconnected.

### Residual risk

AgentGate itself holds a `CREATEROLE` credential and authors every grant it delegates — a compromise of the AgentGate host (its master password plus the encrypted resource store) is equivalent to compromising that admin role's delegable privileges, not just one resource. Scope `agentgate_admin`'s own grants as tightly as you would any credential AgentGate is trusted to hand out.

## SSH Broker

Beyond static API keys, OAuth tokens, and database roles, AgentGate can broker **live SSH access**: an agent asks for a named server resource and receives a brand-new, short-lived SSH certificate — never a standing key, never a credential that outlives the request by more than a few minutes.

### The model

AgentGate itself acts as an **SSH certificate authority**. Instead of distributing a per-server keypair, it holds one CA keypair that every enrolled server is configured to trust, and it mints a fresh signed certificate for each grant:

- Certificates are **short-lived** — `valid_before` is set to the request time plus `SSH_CERT_TTL_MINUTES` (default 15), and sshd enforces that expiry natively. There is no reaper: an expired certificate simply stops being accepted for new logins.
- Certificates are **principal-pinned** — each registered resource carries a fixed login principal (`agentgate ssh-add ... --principal`), and every certificate issued for that resource is valid only for that principal, never whatever the agent asks for.
- Certificates are **`permit-pty`-only** — agent/port/X11 forwarding and user-rc execution are never included as extensions, and this extension set is fixed in code, not configurable per request. A resource can also carry a `force-command`, which sshd runs in place of whatever command the client requests.

### One-time setup

```bash
agentgate ssh-ca-init   # creates the CA keypair, prints its public key line
```

Install the printed public key on each server you want to enroll, then trust it in that server's `sshd_config`:

```bash
# /etc/ssh/agentgate_ca.pub  (paste the public key line printed above)
# sshd_config:
TrustedUserCAKeys /etc/ssh/agentgate_ca.pub
```

Reload sshd (e.g. `systemctl reload sshd`) to pick up the new trust anchor. `agentgate ssh-ca-pub` reprints the CA's public key line at any time, and `ssh-ca-init` refuses to run a second time rather than silently re-keying trust every enrolled server already relies on.

### Registering a server

```bash
agentgate ssh-add web-1 --host 10.0.0.5 --port 22 --principal deploy \
  --force-command "systemctl restart myapp"
```

`--force-command` is optional — omit it to let the certificate's holder run whatever command they pass to `ssh`. `agentgate ssh-list` shows registered resources (host/port/principal/force-command); `agentgate ssh-remove <name>` deletes one. Both are recorded as operator actions in the audit log.

### Agent usage

An agent requests a certificate over MCP, then uses it directly with the system `ssh` client:

```
ssh_certificate_request(agent="claude-code", agent_key="<key>", resource="web-1")
  -> {granted: true, host: "10.0.0.5", port: 22, username: "deploy",
      private_key: "...", certificate: "...", expires_at: "2026-07-06T15:15:00+00:00",
      reason: "auto-approved by policy 'deploy-web'"}
```

```bash
ssh -i agent_key -o CertificateFile=agent_key-cert.pub deploy@10.0.0.5
```

Every certificate's `key_id` is `agentgate:<agent>:<resource>` (e.g. `agentgate:claude-code:web-1`), which sshd writes to its own logs on each login — so every session traces back to the agent and resource that requested it, independent of AgentGate's own audit log.

### Residual risk

AgentGate holds a CA key that every enrolled server trusts — compromise of that key means access to all enrolled servers as any registered principal, until `TrustedUserCAKeys` is removed from each server's `sshd_config`. There is no pre-expiry revocation (no certificate revocation list/KRL): a certificate issued before compromise is detected remains valid until it naturally expires. The `SSH_CERT_TTL_MINUTES` window is the control — keep it short.

## AWS Broker

Beyond static API keys, OAuth tokens, database roles, and SSH certificates, AgentGate can broker **live AWS access**: an agent asks for a named role resource and receives temporary STS credentials via `AssumeRole` — never a standing access key, never credentials that outlive the request by more than a few minutes.

### The model

AgentGate holds one dedicated IAM user's access key (encrypted at rest) whose IAM policy allows **only** `sts:AssumeRole` on the registered role ARNs. On each grant it calls STS with `RoleSessionName=agentgate-<agent>-<resource>` and returns the temporary keypair + session token:

- Credentials are **short-lived** — `DurationSeconds` is set to `AWS_CRED_TTL_MINUTES × 60` (default 15, STS floor 900 seconds). AWS enforces expiry natively. There is no reaper.
- Credentials are **role-scoped** — each registered resource carries a fixed IAM role ARN and region; the agent supplies only the resource name (a dict key). An optional `ExternalId` is forwarded when configured.
- Every assumption is **CloudTrail-visible** — the session name embeds the agent and resource, so AWS-side logs trace back independently of AgentGate's audit log.

### One-time setup

Create scoped IAM roles for each workload (S3 reader, Lambda invoker, etc.), then create a dedicated broker IAM user whose **only** policy is `sts:AssumeRole` on those role ARNs:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Resource": ["arn:aws:iam::123456789012:role/agent-s3-reader"]
  }]
}
```

Store the broker user's access key in AgentGate (secret never via argv):

```bash
AGENTGATE_AWS_SECRET_KEY=... agentgate aws-key-set AKIA_BROKER_ID
```

### Registering a role

```bash
agentgate aws-add s3-reader \
  --role-arn arn:aws:iam::123456789012:role/agent-s3-reader \
  --region us-east-1 \
  --external-id my-external-id   # optional
```

`--external-id` is optional — omit it when the target role's trust policy does not require one. `agentgate aws-list` shows registered resources (role ARN, region, external-id metadata only — no secrets); `agentgate aws-remove <name>` deletes one. Both are recorded as operator actions in the audit log.

### Agent usage

An agent requests credentials over MCP, then uses them with any AWS SDK or CLI:

```
aws_credential_request(agent="claude-code", agent_key="<key>", resource="s3-reader")
  -> {granted: true, access_key_id: "ASIA...", secret_access_key: "...",
      session_token: "...", expiration: "2026-07-06T15:15:00+00:00",
      region: "us-east-1", reason: "auto-approved by policy 'cc-aws'"}
```

The `RoleSessionName` is `agentgate-<agent>-<resource>`, truncated to 64 characters if needed (STS charset `[\w+=,.@-]`). If the agent name contains characters outside that charset, the request is denied.

### Residual risk

AgentGate holds an IAM access key that can assume every registered role — compromise of the AgentGate host (master password plus encrypted stores) is equivalent to compromising that broker user's `AssumeRole` privileges on all registered roles, not just one resource. Mitigations: scope the broker user's IAM policy to `sts:AssumeRole` on only those specific role ARNs, keep the key encrypted at rest, and rely on CloudTrail session-name attribution. There is no pre-expiry revocation of issued STS credentials (AWS provides none short of revoking the role's sessions) — the `AWS_CRED_TTL_MINUTES` window is the control; keep it short.

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
- `DB_RESOURCES_PATH` → `data/db_resources.json` (encrypted PostgreSQL resource definitions)
- `DB_CRED_TTL_MINUTES` → lifetime (in minutes) of a minted ephemeral database role (default `15`)
- `DB_REAP_INTERVAL_SECONDS` → how often the background reaper sweeps for and drops expired database roles (default `30`)
- `SSH_CA_PATH` → `data/ssh_ca.json` (encrypted SSH certificate authority keypair)
- `SSH_RESOURCES_PATH` → `data/ssh_resources.json` (encrypted SSH server resource definitions)
- `SSH_CERT_TTL_MINUTES` → lifetime (in minutes) of an issued SSH certificate (default `15`)
- `AWS_KEY_PATH` → `data/aws_key.json` (encrypted broker IAM access key)
- `AWS_RESOURCES_PATH` → `data/aws_resources.json` (registered AWS role resource definitions)
- `AWS_CRED_TTL_MINUTES` → lifetime (in minutes) of issued STS credentials (default `15`, STS floor 15)

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

Expected: 247 passed, 3 skipped (the skips are integration tests gated on AGENTGATE_TEST_PG_DSN / AGENTGATE_TEST_SSH_HOST and a deploy-gated OAuth test), covering encryption round-trips, agent authentication, policy evaluation (globs, time windows, hard deny, hot reload, shadowing lint), two-tier approval with flood caps, fail-closed error paths, secret-free audit output, and an end-to-end MCP call over the real HTTP transport including Host-header rejection.
