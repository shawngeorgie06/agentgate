# AgentGate SSH Broker — Design

**Date:** 2026-07-05
**Status:** Approved
**Depends on:** V1 core (auth/policy/escalation/audit/MCP spine), infra-broker patterns (2026-07-02 spec)

## Problem

Agents need shell access to servers — deploys, log inspection, service restarts — but handing an agent a real SSH private key is a standing credential with unbounded lifetime and scope. The DB broker solved this shape for PostgreSQL; this subsystem solves it for SSH.

## Decision summary

| Decision | Choice |
|---|---|
| Mechanism | **SSH user certificates** (AgentGate is a CA; servers trust it via `TrustedUserCAKeys`) |
| Key custody | **Broker generates a fresh Ed25519 keypair per grant**; private key + cert returned in the tool response (same posture as the DB password) |
| Cert scope | **Principal (login user) pinned per resource + optional force-command**; agent-/port-/X11-forwarding and user-rc always disabled; `permit-pty` only |
| Expiry | `valid_before = now + TTL` (default 15 min); **sshd enforces expiry natively — no reaper** |
| Revocation before expiry | Out of scope (no KRL distribution); TTL is the control — documented |
| Crypto | `cryptography`'s `SSHCertificateBuilder` (already a dependency, ≥42; verified end-to-end on 49.0.0). No new deps, no shelling out, no network at mint time |
| Policy engine | **Unchanged.** The resource name occupies the credential slot, exactly like DB resources and OAuth connections |

Rejected alternatives: ephemeral `authorized_keys` entries (requires a standing admin credential on every server + reaper + mint-time network dependency); broker-as-jump-proxy (heavyweight always-on proxy, not a V2 subsystem); agent-submitted public keys (better custody but adds agent-side key management and invites keypair reuse that undermines ephemerality — may revisit as an optional parameter later).

## Architecture

One-time operator setup:

1. `agentgate ssh-ca-init` — generates an Ed25519 CA keypair, stores the private key encrypted (master password, Argon2id + AES-256-GCM), refuses to overwrite an existing CA.
2. `agentgate ssh-ca-pub` — prints the CA public key line. Operator installs it on each target server:
   `TrustedUserCAKeys /etc/ssh/agentgate_ca.pub` in `sshd_config`, then `systemctl reload sshd`.
3. `agentgate ssh-add <name> --host H --port 22 --principal deploy [--force-command "systemctl restart myapp"]` — registers a server resource.

From then on no per-server credential exists anywhere. Grant flow:

```
agent → ssh_certificate_request(agent, agent_key, resource)
  → _authenticate            unknown agent → audited deny; never escalates
  → MANUAL mode              → escalate to operator [y/n] (flood cap; timeout → expired)
  → policy evaluate          resource name in the credential slot (globs, hard-deny)
  → _grant_ssh:
      resources.get(name)    KeyError → "unknown ssh resource" deny;
                             other store error → audited generic deny
      ca_store.load()        missing CA → audited deny "ssh CA not initialized";
                             decrypt failure → audited generic deny
      generate Ed25519 keypair; sign user certificate (pure local computation)
  → audit approved (username=principal, key_id, expires_at — no key material)
  → {granted: true, host, port, username, private_key, certificate, expires_at, reason}
```

Certificate contents: type USER; principal = resource's login user (only); `valid_after = now`, `valid_before = now + SSH_CERT_TTL_MINUTES`; `key_id = "agentgate:<agent>:<resource>"` (lands in the target's sshd log — every login traces to an agent); critical option `force-command` iff the resource sets one; extensions exactly `{permit-pty}`; serial = random 63-bit int.

Agent usage (documented in README):

```
ssh -i agent_key -o CertificateFile=agent_key-cert.pub deploy@host
```

Denial response shape (all denials, fail closed): `{granted: false, host: null, port: null, username: null, private_key: null, certificate: null, expires_at: null, reason}`.

## Components

| Unit | Responsibility |
|---|---|
| `broker/ssh_ca.py` | Pure crypto, no I/O: `generate_ca()`, `generate_keypair()`, `sign_certificate(ca_key, public_key, *, key_id, principal, ttl_minutes, force_command)` returning the OpenSSH cert line; principal/force-command re-validated at this sink |
| `broker/ssh_validation.py` | Leaf module (imported by ssh_ca + CLI, imports neither): `PRINCIPAL_RE` (POSIX username: `[a-z_][a-z0-9_-]{0,31}`), `validate_principal`, `validate_force_command` (non-empty, printable, no NUL/newline/CR). Same one-canonical-pattern discipline as `broker/role_naming.py` |
| `broker/ssh_ca_store.py` | EncryptedStore subclass holding the single CA private key (OpenSSH PEM, encrypted); `initialize()` fails if a CA already exists; `load()` raises if absent |
| `broker/ssh_resource_store.py` | `SshResource(name, host, port, principal, force_command: str \| None, created_at)` — nothing secret in it. Subclasses `EncryptedStore` like `DbResourceStore`, but with NO encrypted fields (all values stored as-is) — reuse buys the 0600 perms, atomic writes, and per-access disk re-read, not encryption. `list_metadata()` returns everything (no secret to exclude) |
| `broker/mcp_server.py` | `request_ssh_certificate` / `_grant_ssh` / `_escalate_ssh` / `_ssh_deny`, transcribed from the db path; `Broker.__init__` gains `ssh_resources`, `ssh_ca` (both default None; None → fail-closed deny) |
| `broker/config.py` | `SSH_CA_PATH` (default `<home>/ssh_ca.json`), `SSH_RESOURCES_PATH` (default `<home>/ssh_resources.json`), `SSH_CERT_TTL_MINUTES` (default 15, int ≥ 1) |
| `cli/commands.py` | `ssh-ca-init`, `ssh-ca-pub`, `ssh-add`, `ssh-list`, `ssh-remove`; add/remove/ca-init audited via `log_operator` (subjects are names only) |
| `broker/main.py` | `build_broker` wires `SshResourceStore` + `SshCaStore`. No reaper — nothing to reap |

MCP tool: `ssh_certificate_request` (underscores, matching `db_credential_request` / `token_request`), bringing the tool count to 8 and the grant-or-change count to 5.

## Security model

- **Residual risk (documented honestly):** AgentGate holds a CA private key that every enrolled server trusts. CA compromise = access to all enrolled servers as any registered principal until operators remove `TrustedUserCAKeys`. Mitigations: encrypted at rest under the master password; never leaves the broker; signing is local (no transit); grants are short-TTL so any single credential's exposure window is minutes.
- **No pre-expiry revocation:** KRL generation/distribution is out of scope. TTL is the control. Stated in the README beside the CA-compromise note.
- **Principal pinning at the sink:** the agent supplies only the resource *name* (a dict key). Principal and force-command come from the operator-registered resource, are validated at `ssh-add` time, and are re-validated inside `sign_certificate` before being placed in the cert — validate-at-input-AND-sink, the `db_grants` discipline. No agent-supplied value ever reaches certificate fields.
- **key_id injection guard:** `key_id` embeds the agent name; agent names are already constrained by AgentStore registration, but `sign_certificate` still rejects a key_id containing NUL/newline (defense in depth; it is a free-text field in the cert that lands in server logs).
- **Secret hygiene:** the generated private key appears only in the tool response; any dataclass carrying it uses `field(repr=False)`; never in audit/logs/errors/reasons. The certificate is public material but is also kept out of the audit (noise); the audit records `username` (principal), `key_id`, and expiry via the existing optional-field pattern (`AuditLogger.log` gains `key_id: str | None = None`).
- **Fail-closed paths:** unauthenticated, flood cap, policy hard-deny, escalation timeout/denial, unknown resource, uninitialized CA, store/decrypt failure, signing exception (generic reason, never the exception text) — each writes an audited `decision="denied"` (or `"expired"`) row and returns the full null-field shape.
- **Cert hardening defaults:** no agent-forwarding, no port-forwarding, no X11-forwarding, no user-rc; `permit-pty` only. Not configurable in V2 (YAGNI; loosening would need a deliberate design pass).

## Error handling

| Failure | Behavior |
|---|---|
| CA not initialized (`ssh-ca-init` never run) | Audited deny, reason `"ssh CA not initialized"` |
| CA store decrypt failure (tampered/wrong password) | Audited deny, generic reason — never the crypto error |
| Unknown resource name | Audited deny, `"unknown ssh resource '<name>'"` |
| Resource store failure (non-KeyError) | Audited deny, generic reason |
| Signing raises | Audited deny, `"could not issue certificate for '<name>'"` |
| `ssh-ca-init` when CA exists | Exit 1, message; existing CA untouched (re-keying every server's trust is deliberate, not accidental) |
| `ssh-add` invalid principal/force-command | Exit 2, nothing stored, no audit row |
| `ssh-remove` unknown name | Exit 1, stderr message, no audit row |

## Testing

- **Unit (`tests/test_ssh_ca.py`):** signed cert parsed back with `cryptography`'s `load_ssh_public_identity` — asserts type USER, exact principal, validity window = now..now+TTL, key_id format, force-command present iff configured, extensions exactly `{permit-pty}`, distinct serials/keys across grants; sink re-validation rejects bad principal, bad force-command, newline-bearing key_id.
- **Stores (`tests/test_ssh_ca_store.py`, `tests/test_ssh_resource_store.py`):** CA persists encrypted (raw file lacks the PEM), initialize-twice refuses, load-absent raises; resource CRUD + metadata.
- **Broker path (`tests/test_ssh_tool.py`):** transcribed from `test_db_tool.py` — every denial path audits + returns the full null shape; auth strictly before escalation; private key never in the audit file; CA-missing and decrypt-failure fail closed; tool registered as exactly `ssh_certificate_request`.
- **CLI (`tests/test_ssh_cli.py`):** ca-init/ca-pub/add/list/remove happy paths + validation failures + operator audit rows.
- **Config (`tests/test_config.py` additions):** defaults, overrides, TTL ≥ 1.
- **Integration (skip-gated on `AGENTGATE_TEST_SSH_HOST`):** against a real sshd configured to trust a test CA — cert login succeeds as the pinned principal, an expired cert is refused, force-command output is the forced command's, port-forwarding refused.

## Out of scope (V2)

KRL revocation; host certificates (server→agent trust); agent-submitted public keys; per-grant source-address pinning; session recording; command allowlists beyond a single force-command; Windows/non-OpenSSH targets.
