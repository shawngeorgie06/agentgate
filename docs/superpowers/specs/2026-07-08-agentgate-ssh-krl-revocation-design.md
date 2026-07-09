# AgentGate SSH CA Revocation (KRL) — Design Spec

**Date:** 2026-07-08
**Status:** Approved (brainstorming)
**Branch:** feature/oauth-broker
**Builds on:** SSH broker (2026-07-05, commits 7e67b9c..4d966e4)

## Goal

Let the operator revoke a still-valid AgentGate-issued SSH certificate *before*
its TTL expires. The shipped SSH broker explicitly documented this gap ("no
pre-expiry revocation — TTL is the only control"). This closes it.

## Decisions (locked during brainstorming)

1. **Revocation granularity: by `key_id` (agent+resource).** Revoke the
   `key_id = agentgate:<agent>:<resource>`, which kills every live AND
   future-dated certificate for that agent on that resource at once. The
   key_id is deterministic from `(agent, resource)`, so **no issuance-time
   tracking is required** and the signing path (`broker/ssh_ca.py`) is
   unchanged. Semantically: "cut this agent off this server."
2. **KRL generation: shell out to `ssh-keygen -k`** behind an injectable
   executor seam. OpenSSH owns the KRL wire format; a hand-rolled
   implementation of a security file where a subtle bug means "revocation
   silently does not work" is rejected (YAGNI + risk). Adds a runtime
   dependency on the `ssh-keygen` binary — near-universal on a host already
   running an SSH CA, and isolated behind the seam so unit tests never invoke
   it.
3. **Two enforcement layers** (see Architecture): the server-side KRL AND a
   broker-side issuance denial.
4. **Operator-only, CLI-driven.** No new MCP tool — agents never drive
   revocation (agent-driven revocation would be a DoS vector). Tool count
   stays at 9.

## Architecture

AgentGate becomes an SSH CA that can revoke, enforced at two layers:

- **Server layer (the KRL):** the broker materializes an OpenSSH KRL file
  listing revoked key_ids. Operators deploy it to each server's
  `sshd_config RevokedKeys` **out of band** — the same trust model already
  used to deploy the CA public key via `TrustedUserCAKeys`. sshd then rejects
  any presented cert whose key_id is revoked, regardless of remaining TTL.
  The broker does NOT push to servers (no server inventory — consistent with
  the shipped SSH broker).
- **Broker layer (issuance denial):** `request_ssh_certificate` consults the
  revocation store and **denies minting** a new cert for a revoked
  `agent+resource`. Revocation therefore bites immediately, even before a
  server pulls the updated KRL, and the broker never hands out a cert servers
  will reject. Fail-closed, defense-in-depth. Broker-layer enforcement reads
  the store directly, so it never depends on a successful KRL write.

## Components

All follow existing broker patterns (leaf validation reuse, EncryptedStore
subclass, injectable executor Protocol with a lazy real impl + a Fake for
tests, CLI subcommands, config additions, skip-gated integration test).

### `broker/ssh_revocation_store.py`
`SshRevocationStore` extends `EncryptedStore`, section `ssh_revocations`.
Persists revoked entries `{key_id, agent, resource, revoked_at, reason}`
(`reason` optional). Encrypted-at-rest gives authenticated (AES-GCM)
integrity — a revocation list is tamper-sensitive — plus 0600, matching
`SshResourceStore`.

Methods:
- `revoke(agent, resource, *, key_id, revoked_at, reason=None) -> None` —
  store/overwrite the entry.
- `unrevoke(key_id) -> bool` — remove; returns False if absent.
- `is_revoked(key_id) -> bool`
- `revoked_key_ids() -> list[str]`
- `list_entries() -> list[dict]` — metadata for `ssh-revoke-list`.

### `broker/ssh_krl.py`
`KrlWriter(Protocol, runtime_checkable)`:
```
def write_krl(ca_public_openssh: str, key_ids: list[str], out_path: str) -> None
```
Real `SshKeygenKrlWriter`:
- **Re-validates every key_id with `validate_key_id`** before writing anything
  (validate-at-the-sink). A single invalid key_id fails the whole write closed
  — no partial KRL.
- Writes the CA public key and a spec file (`id: <key_id>` per line) to temp
  files (0600, in the broker's own dir, deleted in a `finally`).
- Runs `ssh-keygen -k -f <out_path> -s <ca_pub_path> <spec_path>` with a
  **fixed argv, `shell=False`**; all variable data passes via files, never
  argv.
- Uses only the CA **public** key — the CA private key never enters this path.
- Maps `subprocess.CalledProcessError` (stderr can embed local paths) to a
  generic `KrlWriteError("failed to generate KRL")` — subprocess stderr never
  reaches an audit row or a returned reason.

`FakeKrlWriter` for unit tests records calls and writes a sentinel file.

`KrlWriteError(Exception)` raised on generation failure.

### `broker/mcp_server.py`
`Broker.__init__` gains `ssh_revocations: SshRevocationStore | None = None`
(None default, like the other broker stores). In `_grant_ssh`, after
auth/policy/escalation and before signing, check
`ssh_revocations.is_revoked(key_id)`. If revoked → return the full null
denial shape and audit `decision="denied"` with generic reason
`"credential revoked"`; signing is never reached. No new MCP tool.

### `cli/commands.py`
- `ssh-revoke <agent> <resource> [--reason TEXT]` — validate strings, compose
  and `validate_key_id` the key_id, write store (`revoked_at`=now UTC), audit
  `action="ssh-revoke" subject=<key_id>`, then regenerate the KRL. Print KRL
  path + deploy reminder.
- `ssh-unrevoke <agent> <resource>` — remove entry, audit
  `action="ssh-unrevoke"`, regenerate KRL. Absent pairing → exit 1, no audit.
- `ssh-revoke-list` — print revoked key_ids + `revoked_at` + reason (metadata
  only).
- `ssh-krl-write [path]` — regenerate the KRL on demand (retry after a failed
  write, or emit to a chosen path for deployment tooling).

### `broker/config.py`
Add `ssh_revocations_path` (encrypted store) and `ssh_krl_path` (output KRL
file), both anchored to `AGENTGATE_HOME`. Wire `SshRevocationStore` and
`SshKeygenKrlWriter` in `broker/main.py`.

## Data flow

**Revoke:** validate agent+resource → compose+validate key_id → write store
(+reason, revoked_at) → audit `ssh-revoke` → load CA public key from
`SshCaStore` → `KrlWriter.write_krl(all revoked_key_ids)` → print KRL path +
deploy reminder.

**Issuance-time enforcement:** `_grant_ssh` checks `is_revoked(key_id)` before
signing; revoked → null shape + audit denied + generic reason, no signing.

**Unrevoke:** remove entry → audit `ssh-unrevoke` → regenerate KRL (key_id
drops out). Forward-looking: also re-permits the agent acquiring that resource.

**KRL deployment (out of band, documented):** operator copies `ssh_krl_path`
to each server and sets `RevokedKeys /etc/ssh/agentgate_krl` in `sshd_config`.
The broker owns generation, not distribution.

## Security & error handling

- **Spec-file injection (the sharp edge):** the `ssh-keygen -k` spec is
  line-oriented (`id: <key_id>`). A newline in a key_id could inject a
  directive line. Mitigation: `write_krl` re-validates every key_id with
  `validate_key_id` (charset + `isprintable`, rejects `\n`/control/Unicode
  line separators) before writing the spec; one bad key_id fails the whole
  write closed. Fixed argv, `shell=False`, temp files not argv.
- **No-leak:** no secret is involved (key_ids/agent/resource/reason are
  non-secret — key_ids already appear in sshd logs). `ssh-keygen` stderr is
  swallowed to a generic `KrlWriteError`; the CA private key never enters the
  KRL path.
- **Fail-closed ordering:** on `ssh-revoke`, record store + audit FIRST, then
  write KRL. A failed KRL write does not lose the revocation (broker-layer
  denial already active; operator re-runs `ssh-krl-write`). Issuance denial
  reads the store, never the KRL file.
- **Exits:** invalid/unknown agent or resource → exit 2, no store write, no
  audit. `ssh-unrevoke` of a non-revoked pairing → exit 1, no audit (mirrors
  `ssh-remove`/`aws-remove`). KRL write failure → exit 1, store already
  updated, message says retry `ssh-krl-write`. Missing CA → exit 1, generic
  message.
- **Store integrity:** `SshRevocationStore` is AES-GCM authenticated + 0600;
  an attacker cannot silently drop an entry without failing decryption.

## Testing

- `tests/test_ssh_revocation_store.py` — CRUD + persistence across reload +
  encrypted-at-rest (raw file has no plaintext key_id) + unrevoke-absent False.
- `tests/test_ssh_krl.py` — `FakeKrlWriter` contract; **sink injection test**
  (key_id with `\n`/`serial:`/control chars raises before any spec write, no
  partial output); generic-error mapping (subprocess failure → `KrlWriteError`
  with no path/stderr text).
- `tests/test_ssh_tool.py` (extend) — `request_ssh_certificate` denied when
  key_id revoked: full null shape, `decision="denied"` audited, generic
  `"credential revoked"` reason, signing never invoked, private-key field None;
  non-revoked pairing still succeeds.
- `tests/test_ssh_cli.py` (extend) — `ssh-revoke` writes store + audits +
  calls writer; `ssh-revoke-list` metadata only; `ssh-unrevoke` removes +
  audits + rewrites; invalid agent/resource → exit 2 no audit;
  unrevoke-absent → exit 1 no audit; KRL-write-failure → exit 1 but store
  updated.
- `tests/test_config.py` (extend) — `ssh_revocations_path` + `ssh_krl_path`
  derive from `AGENTGATE_HOME`.
- `tests/test_ssh_krl_integration.py` — skip-gated on
  `shutil.which("ssh-keygen")`: generate a real KRL from a real CA pubkey,
  verify with `ssh-keygen -Qf <krl> <cert>` that a revoked cert reports
  revoked and a non-revoked one does not.

## Docs

README gains an SSH-revocation subsection: the two-layer model, the
`RevokedKeys` deployment step, and the four CLI commands. Tool-count line
stays at 9 MCP tools (no new agent tool).

## Out of scope (YAGNI)

- Agent-driven / self-service revocation (DoS vector).
- Automatic KRL distribution to servers (no server inventory; out-of-band by
  design).
- Serial-based or per-issuance revocation (granularity decision #1).
- Signed KRLs (sshd reads `RevokedKeys` as a trusted local file).
