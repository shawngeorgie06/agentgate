# Agent identities and revocation

AgentGate authenticates HTTP MCP clients using separately enrolled identities. Each credential maps to one agent name; that name is selected by the server, not a request argument. Existing YAML policies still decide access to Gmail and API keys. Registration does not grant permissions.

## Operator workflow

Restart the app once to load this version. Its initial screen is **Agents**. Your existing `mcp-token` is automatically enrolled as `agentgate-local`; it keeps working with the same Gmail policies and credential file.

1. Register a unique agent name in **Agents** and choose its credential lifetime. New credentials expire after 720 hours (30 days) by default; supported lifetimes are 1–8760 hours.
2. The broker writes a new credential file with mode 0600 into `agent-credentials/` next to the registry. The app displays the file path and a command to copy; the bearer secret is not returned to the browser or audit log.
3. Use that file with the agent process. The app's example command checks the broker without showing credentials. Agent names may contain letters, digits, dots, underscores, and hyphens, up to 64 characters. `operator` and `SYSTEM` are reserved.
4. Add an agent-specific YAML policy if it should receive automatic access. Existing policy administration still requires operator approval. A policy proposal's full frozen contents must be reviewed before approval. Agents cannot approve or register themselves.
5. Click **Revoke access**, review the agent name, and confirm. Revocation is effective without restarting the server. Expired and revoked identities remain visible for history; names cannot be reused. Token rotation/reissuing an existing identity is not implemented yet.

Use the command shown by the app, substituting the private file path if configuring another client. Global CLI options come before the action. `--agent` is now optional; if supplied it is an identity assertion and must match the enrolled credential. Omitting it lets the server determine identity.

## Enforcement

- The HTTP bearer verifier checks the persistent registry. Every MCP tool rechecks identity, including requests on an existing session.
- Changing an `agent` argument cannot impersonate another identity or borrow its policies.
- Requests waiting for approval recheck identity after approval. Gmail operations also check after waiting for the provider lock or token refresh, immediately before dispatch.
- Revocation blocks future access through AgentGate; it cannot undo an operation already dispatched, retract data already returned, or invalidate a raw provider API key already exported by the legacy credential tool.
- Every Gmail send still requires explicit approval of its snapshotted contents. Agents never receive Gmail OAuth credentials.
- Operator app actions are separate from agent identities. Revoking `agentgate-local` does not lock the owner out of the app. Owner-initiated sends are attributed to `operator` and still require send approval.

The registry stores SHA-256 hashes of high-entropy bearer credentials, not their plaintext. API responses and activity records expose identity metadata, not credentials. The exported private credential files must remain accessible only to their intended agent process and operator.

## Migration and storage

`AGENTS_PATH` configures the SQLite registry. If omitted, it defaults to `agents.sqlite3` next to `CREDENTIALS_PATH`. Registry and credential-export files are outside version control. Keep one broker process per encrypted provider store; the registry's transactions do not make the older credential store safe for multiple brokers.

`--token-file` imports the original local agent credential under `agentgate-local`. `--bootstrap-agent NAME` changes that migration identity for a separately configured installation. Import is idempotent: it does not reactivate revoked or expired identities, replace credentials, or reset expiry. The migrated original credential has no expiry to preserve existing clients; it can be revoked in the app. New registrations have finite expiry.

After revoking the migrated credential, the app still starts using its independent operator credential. Agent calls with the old file remain denied after restart. Register a new identity and configure policies for it rather than deleting the registry to regain access.

STDIO clients use a trusted launcher identity selected with `--stdio-agent NAME` (default `agentgate-local`). They do not authenticate through the HTTP registry; their identity is assigned by the operator launching their dedicated process. Registry revocation applies to HTTP identities, not to an independently launched STDIO process. In-process integrations must similarly supply an explicit trusted identity when registering Gmail tools.

## Boundary and deferred work

This remains a local, single-user prototype. AgentGate authenticates possession of a credential, not the agent executable or its human-readable name. A process with unrestricted filesystem access as your macOS user may read private credential files or bypass the gateway. OS sandboxing, credential rotation, a permissions editor, provider revocation, and additional connectors are separate milestones. The legacy raw API-key flow still exports approved keys; its returned expiry remains metadata rather than provider-enforced key expiry.
