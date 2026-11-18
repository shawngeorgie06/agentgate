# AgentGate

AgentGate is a local credential broker and approval gate for AI agents. Agents connect to it over MCP and ask it to use your credentials, such as API keys, Gmail and GitHub. AgentGate checks each request against your policies and per-agent permissions. Anything risky waits for you to approve it in a local web app, by text over iMessage, or in the terminal. Every decision goes into an append-only audit log.

It runs on your own machine. On macOS it can run in the background as a login service.

## What it does

- **Encrypted credential store:** Argon2id key derivation and AES-256-GCM encryption, with a per-credential salt and nonce. Gmail and GitHub tokens never leave the broker.
- **Agent identities:** each agent gets its own bearer credential, which can expire or be revoked without a restart. A caller can't claim a different identity by passing another agent name.
- **Policies and permissions:** YAML policies with time windows and auto-approval rules for API keys. Per-agent allow, ask or deny rules for Gmail and GitHub, plus temporary grants of 1–1440 minutes.
- **Approvals:** sending email, creating GitHub issues and adding policies always need your approval. Everything else follows the current mode (AUTO or MANUAL) and the matching policy.
- **Gmail:** search, read and create drafts. Sending a draft needs approval.
- **GitHub:** list repositories and issues and read files. Creating an issue needs approval.
- **Operator app:** a local browser UI at `http://127.0.0.1:8765/app` for agents, connections, permissions, temporary access, inbox and drafts, approvals and recent activity.
- **iMessage assistant:** ask about your email and GitHub, draft email replies, and approve requests by texting yourself. It uses Apple's on-device model.
- **macOS background service:** a per-user LaunchAgent with the vault unlock saved in your Keychain, plus a small native `AgentGate.app` opener.
- **Audit log:** one JSON line per decision. It never records credential values or tokens.

## Documentation

| Guide | Covers |
| --- | --- |
| [Operator app](docs/app.md) | Setup, screens, local security boundary, sample-data preview |
| [Agent identities](docs/agents.md) | Registering, revoking, enforcement, migration |
| [Permissions](docs/permissions.md) | Per-agent Gmail and GitHub rules, temporary grants |
| [Gmail](docs/gmail.md) | Google OAuth setup, tools, agent commands |
| [iMessage](docs/imessage.md) | Pairing, questions, reply drafts, approvals by text, privacy |
| [Background service](docs/background.md) | macOS LaunchAgent, Keychain unlock, install and uninstall |

## Quickstart

### Install

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r requirements.txt
source .venv/bin/activate
cp .env.example .env
```

The application doesn't load `.env` itself; export the variables in your shell or launcher (Docker Compose loads it through `env_file`). Set `AGENTGATE_MASTER_PASSWORD`, or the broker will prompt for it with `getpass` at startup.

### Store an API key

The value is read from stdin or `AGENTGATE_CRED_VALUE`, never from a command-line argument, so it doesn't show up in process listings:

```bash
echo "<your-api-key>" | python -m cli.commands cred-store anthropic-api-key
```

Other operator commands are `cred-list`, `cred-delete`, `policy-validate`, `status`, `gmail-connect`, `gmail-disconnect` and `mcp-token-create`.

### Try it without real credentials

```bash
python -m examples.demo                # terminal approvals with temporary dummy credentials
.venv/bin/python examples/app_demo.py  # operator app with sample data
```

### Run the broker

AgentGate runs one broker process per credential store and holds a lock to enforce that. Pick one way to run it:

**Operator app (recommended).** This serves authenticated MCP at `http://127.0.0.1:8765/mcp` and opens the app at `/app`. Create the agent token and a separate operator token once:

```bash
python -m cli.commands mcp-token-create --path ~/.config/agentgate/mcp-token
python -m cli.commands mcp-token-create --path ~/.config/agentgate/operator-token
python -m broker.main --app \
  --token-file ~/.config/agentgate/mcp-token \
  --operator-token-file ~/.config/agentgate/operator-token
```

On first launch, the `--token-file` credential is enrolled as the `agentgate-local` identity. Register more agents in the app's **Agents** screen. Approvals happen in the app, so terminal approvals are turned off in this mode. Pass `--no-open` to stop it opening a browser, or `--port` to change the port.

**HTTP without the app.** Run `python -m broker.main --http --token-file …`. This serves the same MCP endpoint, and approvals happen in the terminal.

**STDIO.** Run `python -m broker.main`. An MCP client launches this command and owns stdin and stdout. Requests run as the `--stdio-agent` identity (default `agentgate-local`). Approvals use `/dev/tty`: answer `y` or `n`, enter `s` to switch between AUTO and MANUAL, or `q` to stop. Clients that detach their subprocesses, and desktop clients without a terminal, run headless. In that case the broker needs `AGENTGATE_MASTER_PASSWORD` and a positive `ESCALATION_TIMEOUT_SECONDS`, and requests that need an operator time out and are denied.

**Background on macOS.** See [docs/background.md](docs/background.md) to build `AgentGate.app` and install the login service. It runs the broker in app mode.

### Connect services

- **Gmail:** run `python -m cli.commands gmail-connect` or use **Connections** in the app. See [docs/gmail.md](docs/gmail.md).
- **GitHub:** create a fine-grained personal access token limited to the repositories agents should see. Give it Metadata and Contents read access, Issues read access to list issues, and Issues write access only if you want issue creation (which needs approval). Enter the token in the app's **Connections** form. It is encrypted and never returned to agents.

Disconnecting only removes the local credential. To revoke access at Google or GitHub, do that on their side too.

## Agent access

### MCP tools

| Tool | Purpose |
| --- | --- |
| `credential.request` | Request an API key by name as the authenticated identity |
| `policy.list`, `policy.validate` | Inspect or check policies |
| `policy.add` | Propose a policy; always needs operator approval |
| `broker.status` | Mode, policy count, request and escalation counts, uptime |
| `gmail.search`, `gmail.read`, `gmail.draft` | Search, read and create unsent drafts |
| `gmail.send_draft` | Send an existing draft; always needs approval |
| `github.account`, `github.repos`, `github.repo` | Connected account and repositories |
| `github.read_file`, `github.issues` | Read a UTF-8 file of up to 1 MiB; list issues |
| `github.create_issue` | Create one issue; always needs approval of the exact repository, title and body |

Identity comes from the bearer credential (HTTP) or the launcher's configured identity (STDIO). An optional agent-name argument is only an assertion, and it must match.

### JSON command-line client

Agents that don't speak MCP can use `cli.agent` against the running broker:

```bash
.venv/bin/python -m cli.agent --token-file /private/path/agent.token status
.venv/bin/python -m cli.agent --token-file /private/path/agent.token search 'is:unread'
.venv/bin/python -m cli.agent --token-file /private/path/agent.token github repos
.venv/bin/python -m cli.agent --token-file /private/path/agent.token github read-file OWNER REPO README.md
```

The commands are `status`, `search`, `read`, `draft`, `send-draft` and `github {account,repos,repo,read-file,issues,create-issue}`. Issue creation needs a stable `--request-id`. Reuse that same ID when you check on an uncertain request: an encrypted ledger blocks a second dispatch, even across restarts. AgentGate never retries a send or an issue creation automatically.

## iMessage assistant

After pairing in the app, text yourself in Messages:

```text
/agent do I have unread email?
/agent draft a reply to the AWS email
/agent list open issues in OWNER/REPO
```

The assistant plans one read-only action per request. It can check unread email, search or read an email, list repositories or issues, read a file, or save a new Gmail reply draft. Then it answers with Apple's on-device model. It can't send email, create issues, edit existing drafts or delete anything. It can also announce pending approvals and accept your reply by text. Sending a threaded reply draft still needs approval in the app.

It needs a Mac with Apple Intelligence, Full Disk Access and Automation permission for Messages, and two helpers (`bin/imsg` and `bin/agentgate-model`). See [docs/imessage.md](docs/imessage.md) for setup, rate limits and privacy.

## Policies

API-key access is decided by `policies/policies.yaml`. Policies are checked in order, and the first match wins:

```yaml
policies:
  - name: claude-code-anthropic
    agent: claude-code          # or "*"
    credential: anthropic-api-key  # or "*"
    access: read
    time_window:                # optional; omit for 24/7
      start: "09:00"
      end: "23:00"
    auto_approve: true
  - name: default-deny
    agent: "*"
    credential: "*"
    auto_approve: false
    escalate: true              # ask the operator instead of denying outright
```

Gmail and GitHub access for each agent is set in the app's **Permissions** screen. Those rules are stored by the broker and applied immediately. A temporary grant overrides one saved rule, even an explicit deny, until it expires or you revoke it. Access is checked again just before each call to Gmail or GitHub, so expiry or revocation stops queued work. See [docs/permissions.md](docs/permissions.md).

## Approval modes

- **AUTO:** policies with `auto_approve: true` are granted immediately. Everything else escalates.
- **MANUAL:** every API-key request escalates, and so do Gmail and GitHub reads and drafts.

Sends, issue creation and policy changes always ask, whatever the mode. Switch modes in the app, or by entering `s` in terminal mode. The mode is saved to `state/mode.json` and read fresh on every request.

`ESCALATION_TIMEOUT_SECONDS` limits how long a request waits for you. When it runs out, the request is denied and audited as `expired`. The default of `0` waits forever, which suits interactive use. Headless setups should set a positive value so pending requests don't pile up in memory.

## Audit log

`logs/audit.log` holds one JSON object per line:

```json
{"timestamp": "2026-06-24T14:32:05", "agent": "claude-code", "credential_requested": "anthropic-api-key", "policy_matched": "claude-code-anthropic", "decision": "approved", "mode": "auto", "token_expiry": "2026-06-24T15:32:05"}
```

`decision` is one of `approved`, `denied`, `escalated`, `expired`, `completed` or `failed`. The last two record the outcome of an operation that was carried out, such as a Gmail send, an issue creation or a policy change. For entries that aren't API-key requests, `credential_requested` holds the resource instead, such as `github:write` or `imessage:gmail_search`. Credential values and issued tokens are never written.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `AGENTGATE_MASTER_PASSWORD` | prompt | Vault password (the background service reads it from Keychain instead) |
| `CREDENTIALS_PATH` | `./data/credentials.json` | Encrypted credential store |
| `AGENTS_PATH` | next to the store | Agent identity registry |
| `POLICIES_PATH` | `./policies/policies.yaml` | Policy file |
| `STATE_PATH` | `./state/mode.json` | Approval mode |
| `LOGS_PATH` | `./logs/audit.log` | Audit log |
| `TOKEN_TTL_MINUTES` | `60` | `token_expiry` on granted API keys. This is metadata only: the raw key is returned and not revoked at expiry |
| `ESCALATION_TIMEOUT_SECONDS` | `0` | Approval wait before denying; `0` waits forever |
| `GMAIL_CLIENT_PATH` | `oauth-client.json` next to the store | Google OAuth client file |
| `AGENTGATE_IMSG_PATH`, `AGENTGATE_MODEL_HELPER` | `bin/` in the config directory | iMessage helpers |

Invalid values stop startup with a clear error.

## Docker

```bash
docker compose build
docker compose up
```

The container runs the STDIO broker with `policies`, `state`, `logs` and `data` mounted from the host. Writes are atomic, but there's no locking between instances, so run only one container per store. The operator app, iMessage and background service are local macOS features and aren't part of the image.

## Project layout

| Path | Contents |
| --- | --- |
| `broker/main.py` | Entry point, startup modes, process lock |
| `broker/mcp_server.py`, `gmail_tools.py`, `github_tools.py` | MCP tools |
| `broker/credential_store.py`, `agent_registry.py`, `http_auth.py` | Vault, identities, bearer auth |
| `broker/policy_engine.py`, `permissions.py`, `grants.py`, `access.py`, `approval.py` | Access decisions and the approval queue |
| `broker/dashboard.py`, `grants_dashboard.py`, `connections.py`, `web/` | Operator app |
| `broker/imessage_*.py`, `apple_model.py` | iMessage bridge, assistant and on-device model |
| `broker/mac_install.py`, `mac_service.py`, `mac_keychain.py`, `native/` | macOS app, LaunchAgent, Keychain helper |
| `cli/commands.py`, `cli/agent.py` | Operator and agent command-line tools |
| `examples/` | Demos and smoke checks with sample data |

## Testing

```bash
python -m pytest
```

Tests that use the native Keychain helper or the real on-device model skip themselves on machines where those aren't available.
