# AgentGate SSH CA Revocation (KRL) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the operator revoke a still-valid AgentGate-issued SSH certificate before its TTL expires, enforced both server-side (OpenSSH KRL) and broker-side (issuance denial).

**Architecture:** A new encrypted `SshRevocationStore` records revoked `key_id`s (`agentgate:<agent>:<resource>`). An injectable `KrlWriter` seam shells out to `ssh-keygen -k` to materialize an OpenSSH KRL that operators deploy to servers' `RevokedKeys` out of band. `_grant_ssh` additionally consults the store and denies minting a cert for a revoked pairing (fail-closed, defense-in-depth). Operator-only via four CLI subcommands — no new MCP tool.

**Tech Stack:** Python 3.11+, `cryptography` (existing, for the SSH CA), OpenSSH `ssh-keygen` binary (new runtime dependency, isolated behind the seam), pytest (`asyncio_mode = auto`).

## Global Constraints

- **No secret is involved in this subsystem**, but the discipline still holds: nothing (key_ids, agent/resource names, reasons, subprocess stderr) that could forge a log line or leak a filesystem path may reach an audit row or a returned `reason`. `ssh-keygen` stderr is caught and replaced with a generic message.
- **Fail closed everywhere.** If revocation status cannot be determined, deny. A failed KRL write must not lose the persisted revocation.
- **Validate at input AND at the sink.** Every `key_id` is re-validated with `validate_key_id` (charset + `isprintable`) immediately before it is written to the `ssh-keygen` spec file — this is the injection barrier.
- **The revoked key_id must be byte-identical to the issued key_id.** Both come from the single canonical helper `ssh_key_id(agent, resource)` in the leaf module `broker/ssh_validation.py`; neither path may compose the string itself.
- **The CA private key never enters the KRL path** — only the CA public key is used.
- **Operator-only.** No new MCP tool; tool count stays at 9. Revocation is never agent-driven.
- **`ssh-keygen` invoked with a fixed argv, `shell=False`.** All variable data (key_ids, CA pubkey) passes via 0600 temp files, never argv. Temp files are deleted in a `finally`.
- Python style: `from __future__ import annotations` at the top of every new module. Async tests need no decorator (`asyncio_mode = auto`).
- All new stores follow the `EncryptedStore` subclass pattern (0600, per-access disk re-read, `_SECTION`).

---

### Task 1: Canonical key_id helper + `SshRevocationStore`

**Files:**
- Modify: `broker/ssh_validation.py` (add `ssh_key_id`)
- Create: `broker/ssh_revocation_store.py`
- Test: `tests/test_ssh_revocation_store.py`

**Interfaces:**
- Consumes: `broker.encrypted_store.EncryptedStore`.
- Produces:
  - `ssh_key_id(agent: str, resource: str) -> str` → `f"agentgate:{agent}:{resource}"` (leaf module, no broker imports).
  - `SshRevocationStore(EncryptedStore)` with `_SECTION = "ssh_revocations"` and:
    - `revoke(self, *, key_id: str, agent: str, resource: str, revoked_at: str, reason: str | None = None) -> None`
    - `unrevoke(self, key_id: str) -> bool` (False if absent)
    - `is_revoked(self, key_id: str) -> bool`
    - `revoked_key_ids(self) -> list[str]` (sorted)
    - `list_entries(self) -> list[dict]` (sorted by key_id; each `{"key_id", "agent", "resource", "revoked_at", "reason"}`)

- [ ] **Step 1: Write the failing tests**

Create `tests/test_ssh_revocation_store.py`:

```python
from __future__ import annotations

from broker.ssh_revocation_store import SshRevocationStore
from broker.ssh_validation import ssh_key_id


def _store(tmp_path):
    return SshRevocationStore(str(tmp_path / "revocations.json"), "pw")


def test_ssh_key_id_is_canonical():
    assert ssh_key_id("claude-code", "web-1") == "agentgate:claude-code:web-1"


def test_revoke_then_is_revoked(tmp_path):
    s = _store(tmp_path)
    kid = ssh_key_id("claude-code", "web-1")
    assert s.is_revoked(kid) is False
    s.revoke(key_id=kid, agent="claude-code", resource="web-1",
             revoked_at="2026-07-08T00:00:00+00:00", reason="compromised")
    assert s.is_revoked(kid) is True


def test_revocation_persists_across_reload(tmp_path):
    kid = ssh_key_id("claude-code", "web-1")
    _store(tmp_path).revoke(key_id=kid, agent="claude-code", resource="web-1",
                            revoked_at="2026-07-08T00:00:00+00:00")
    assert SshRevocationStore(str(tmp_path / "revocations.json"), "pw").is_revoked(kid)


def test_unrevoke_removes_and_reports(tmp_path):
    s = _store(tmp_path)
    kid = ssh_key_id("claude-code", "web-1")
    s.revoke(key_id=kid, agent="claude-code", resource="web-1",
             revoked_at="2026-07-08T00:00:00+00:00")
    assert s.unrevoke(kid) is True
    assert s.is_revoked(kid) is False
    assert s.unrevoke(kid) is False  # already absent


def test_revoked_key_ids_and_list_entries_sorted(tmp_path):
    s = _store(tmp_path)
    s.revoke(key_id=ssh_key_id("a", "z"), agent="a", resource="z",
             revoked_at="2026-07-08T00:00:00+00:00")
    s.revoke(key_id=ssh_key_id("a", "y"), agent="a", resource="y",
             revoked_at="2026-07-08T00:00:01+00:00", reason="oops")
    assert s.revoked_key_ids() == ["agentgate:a:y", "agentgate:a:z"]
    entries = s.list_entries()
    assert [e["key_id"] for e in entries] == ["agentgate:a:y", "agentgate:a:z"]
    assert entries[0]["reason"] == "oops"
    assert entries[1]["reason"] is None


def test_revoked_key_id_not_plaintext_on_disk(tmp_path):
    kid = ssh_key_id("claude-code", "web-1")
    _store(tmp_path).revoke(key_id=kid, agent="claude-code", resource="web-1",
                            revoked_at="2026-07-08T00:00:00+00:00")
    raw = (tmp_path / "revocations.json").read_text()
    assert kid not in raw  # encrypted at rest
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/test_ssh_revocation_store.py -q`
Expected: FAIL (ImportError: cannot import name `ssh_key_id` / `SshRevocationStore`).

- [ ] **Step 3: Add the canonical helper**

Append to `broker/ssh_validation.py`:

```python
def ssh_key_id(agent: str, resource: str) -> str:
    # The ONE place the certificate key_id is composed. Both the signing sink
    # (broker/mcp_server.py) and revocation (store + CLI) call this so a
    # revoked key_id is byte-identical to the issued one — if they drifted,
    # revocation would silently fail to match. (The role_naming.py lesson.)
    return f"agentgate:{agent}:{resource}"
```

Wait — the revocation store must encrypt its values so `test_revoked_key_id_not_plaintext_on_disk` passes. `SshResourceStore` does NOT encrypt (it stores plaintext for readability). This store encrypts the whole record blob. Create `broker/ssh_revocation_store.py`:

```python
from __future__ import annotations

import json

from broker import crypto
from broker.encrypted_store import EncryptedStore


class SshRevocationStore(EncryptedStore):
    """Revoked SSH certificate key_ids. Encrypted at rest: AES-GCM gives
    authenticated integrity so an attacker cannot silently drop a revocation
    entry without failing decryption. Keyed by key_id."""

    _SECTION = "ssh_revocations"

    def revoke(self, *, key_id: str, agent: str, resource: str,
               revoked_at: str, reason: str | None = None) -> None:
        record = {"agent": agent, "resource": resource,
                  "revoked_at": revoked_at, "reason": reason}
        self._entries()[key_id] = crypto.encrypt(self._key, json.dumps(record))
        self._write(self._data)

    def unrevoke(self, key_id: str) -> bool:
        entries = self._entries()
        if key_id not in entries:
            return False
        del entries[key_id]
        self._write(self._data)
        return True

    def is_revoked(self, key_id: str) -> bool:
        return key_id in self._entries()

    def revoked_key_ids(self) -> list[str]:
        return sorted(self._entries().keys())

    def list_entries(self) -> list[dict]:
        out = []
        for key_id, blob in sorted(self._entries().items()):
            rec = json.loads(crypto.decrypt(self._key, blob))
            out.append({"key_id": key_id, "agent": rec["agent"],
                        "resource": rec["resource"],
                        "revoked_at": rec["revoked_at"], "reason": rec["reason"]})
        return out
```

Note on encryption API: `crypto.encrypt(self._key, plaintext_str)` / `crypto.decrypt(self._key, blob)` are the exact functions `SshCaStore` uses (`broker/ssh_ca_store.py` lines 29, 45). Follow that signature; if it differs, match `SshCaStore`'s usage verbatim.

- [ ] **Step 4: Run to verify they pass**

Run: `python -m pytest tests/test_ssh_revocation_store.py -q`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add broker/ssh_validation.py broker/ssh_revocation_store.py tests/test_ssh_revocation_store.py
git commit -m "feat: SshRevocationStore + canonical ssh_key_id helper"
```

---

### Task 2: `KrlWriter` seam (`ssh-keygen -k`)

**Files:**
- Create: `broker/ssh_krl.py`
- Test: `tests/test_ssh_krl.py`

**Interfaces:**
- Consumes: `broker.ssh_validation.validate_key_id`.
- Produces:
  - `class KrlWriteError(Exception)`
  - `KrlWriter` — `runtime_checkable` Protocol: `def write_krl(self, ca_public_openssh: str, key_ids: list[str], out_path: str) -> None`
  - `class SshKeygenKrlWriter` — real impl (lazy subprocess).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_ssh_krl.py`:

```python
from __future__ import annotations

import os

import pytest

from broker.ssh_krl import KrlWriteError, SshKeygenKrlWriter
from broker.ssh_validation import SshValidationError


class _RecordingRunner:
    """Captures the argv ssh-keygen would be called with, and the spec file
    contents, without invoking a real subprocess."""
    def __init__(self):
        self.argv = None
        self.spec_text = None

    def __call__(self, argv):
        self.argv = argv
        # argv is [ssh-keygen, -k, -f, out, -s, ca_pub, spec]; read the spec.
        self.spec_text = open(argv[-1], encoding="utf-8").read()


def test_write_krl_builds_fixed_argv_and_id_lines(tmp_path):
    rec = _RecordingRunner()
    w = SshKeygenKrlWriter(_runner=rec)
    out = str(tmp_path / "krl")
    w.write_krl("ssh-ed25519 AAAAfakeCA", ["agentgate:a:web-1", "agentgate:b:db-1"], out)
    assert rec.argv[:2] == ["ssh-keygen", "-k"]
    assert "-f" in rec.argv and out in rec.argv
    assert "-s" in rec.argv
    assert "id: agentgate:a:web-1" in rec.spec_text
    assert "id: agentgate:b:db-1" in rec.spec_text


def test_write_krl_rejects_injection_before_any_subprocess(tmp_path):
    # A key_id carrying a newline could inject a second KRL directive.
    # It must be rejected by validate_key_id BEFORE the runner is ever called.
    called = {"n": 0}
    def runner(argv):
        called["n"] += 1
    w = SshKeygenKrlWriter(_runner=runner)
    out = str(tmp_path / "krl")
    with pytest.raises(SshValidationError):
        w.write_krl("ssh-ed25519 AAAAfakeCA", ["agentgate:a:web-1\nserial: 1"], out)
    assert called["n"] == 0
    assert not os.path.exists(out)


def test_write_krl_maps_subprocess_failure_to_generic_error(tmp_path):
    def runner(argv):
        raise RuntimeError("ssh-keygen: /tmp/secret/path: No such file")
    w = SshKeygenKrlWriter(_runner=runner)
    with pytest.raises(KrlWriteError) as ei:
        w.write_krl("ssh-ed25519 AAAAfakeCA", ["agentgate:a:web-1"], str(tmp_path / "krl"))
    # No filesystem path / stderr leaks into the error message.
    assert "/tmp/secret/path" not in str(ei.value)
    assert "failed to generate KRL" in str(ei.value)


def test_temp_files_are_cleaned_up(tmp_path):
    rec = _RecordingRunner()
    w = SshKeygenKrlWriter(_runner=rec)
    w.write_krl("ssh-ed25519 AAAAfakeCA", ["agentgate:a:web-1"], str(tmp_path / "krl"))
    # The spec + ca-pub temp files created under the KRL's dir are gone.
    leftovers = [p for p in os.listdir(tmp_path) if p != "krl"]
    assert leftovers == []
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/test_ssh_krl.py -q`
Expected: FAIL (ImportError).

- [ ] **Step 3: Implement the writer**

Create `broker/ssh_krl.py`:

```python
from __future__ import annotations

import os
import subprocess
import tempfile

from typing import Callable, Protocol, runtime_checkable

from broker.ssh_validation import validate_key_id


class KrlWriteError(Exception):
    """Raised when KRL generation fails. Message is deliberately generic —
    ssh-keygen stderr can embed local filesystem paths and must never leak."""


@runtime_checkable
class KrlWriter(Protocol):
    def write_krl(self, ca_public_openssh: str, key_ids: list[str], out_path: str) -> None:
        ...


def _default_runner(argv: list[str]) -> None:
    # check=True raises CalledProcessError on non-zero exit; stderr is
    # captured (not inherited) so it cannot leak to the operator's console
    # uncontrolled — the caller maps any failure to a generic KrlWriteError.
    subprocess.run(argv, check=True, capture_output=True)


class SshKeygenKrlWriter:
    """Materializes an OpenSSH KRL via `ssh-keygen -k`. The CA public key and
    the revocation spec are passed as 0600 temp files (never argv); the argv
    is fixed and shell=False. Only the CA PUBLIC key is used."""

    def __init__(self, _runner: Callable[[list[str]], None] = _default_runner) -> None:
        self._runner = _runner

    def write_krl(self, ca_public_openssh: str, key_ids: list[str], out_path: str) -> None:
        # Sink re-validation: reject any key_id that could inject a KRL
        # directive (newline/control char) BEFORE writing the spec file. One
        # bad id fails the whole write closed — no partial KRL.
        validated = [validate_key_id(k) for k in key_ids]

        out_dir = os.path.dirname(os.path.abspath(out_path))
        os.makedirs(out_dir, exist_ok=True)
        spec_path = ca_path = None
        try:
            spec_path = _write_temp(out_dir, "".join(f"id: {k}\n" for k in validated))
            ca_path = _write_temp(out_dir, ca_public_openssh + "\n")
            argv = ["ssh-keygen", "-k", "-f", out_path, "-s", ca_path, spec_path]
            try:
                self._runner(argv)
            except Exception:
                raise KrlWriteError("failed to generate KRL") from None
        finally:
            for p in (spec_path, ca_path):
                if p is not None and os.path.exists(p):
                    os.remove(p)


def _write_temp(directory: str, text: str) -> str:
    fd, path = tempfile.mkstemp(dir=directory)
    try:
        os.chmod(path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
    except Exception:
        os.remove(path)
        raise
    return path
```

- [ ] **Step 4: Run to verify they pass**

Run: `python -m pytest tests/test_ssh_krl.py -q`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add broker/ssh_krl.py tests/test_ssh_krl.py
git commit -m "feat: KrlWriter seam over ssh-keygen -k with sink revalidation"
```

---

### Task 3: Config paths (`ssh_revocations_path`, `ssh_krl_path`)

**Files:**
- Modify: `broker/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Produces: `Config.ssh_revocations_path: str`, `Config.ssh_krl_path: str`, both anchored to `AGENTGATE_HOME`/`~/.agentgate` and overridable via `SSH_REVOCATIONS_PATH` / `SSH_KRL_PATH`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_config.py`:

```python
def test_ssh_revocation_and_krl_paths_derive_from_home(tmp_path, monkeypatch):
    from broker.config import Config
    monkeypatch.setenv("AGENTGATE_HOME", str(tmp_path))
    cfg = Config.from_env()
    assert cfg.ssh_revocations_path == str(tmp_path / "ssh_revocations.json")
    assert cfg.ssh_krl_path == str(tmp_path / "ssh_krl")


def test_ssh_krl_path_overridable(monkeypatch):
    from broker.config import Config
    monkeypatch.setenv("SSH_KRL_PATH", "/etc/ssh/agentgate_krl")
    cfg = Config.from_env()
    assert cfg.ssh_krl_path == "/etc/ssh/agentgate_krl"
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/test_config.py -k krl -q`
Expected: FAIL (AttributeError: no `ssh_revocations_path`).

- [ ] **Step 3: Wire the config**

In `broker/config.py`, add to `_default_paths`'s returned dict (after the `SSH_RESOURCES_PATH` line):

```python
        "SSH_REVOCATIONS_PATH": os.path.join(base, "ssh_revocations.json"),
        "SSH_KRL_PATH": os.path.join(base, "ssh_krl"),
```

Add dataclass fields after `ssh_cert_ttl_minutes` (line ~90):

```python
    ssh_revocations_path: str = os.path.join("data", "ssh_revocations.json")
    ssh_krl_path: str = os.path.join("data", "ssh_krl")
```

Add to the `from_env` `cls(...)` call after the `ssh_cert_ttl_minutes=...` block:

```python
            ssh_revocations_path=_require_non_empty(
                get("SSH_REVOCATIONS_PATH"), "SSH_REVOCATIONS_PATH"
            ),
            ssh_krl_path=_require_non_empty(get("SSH_KRL_PATH"), "SSH_KRL_PATH"),
```

- [ ] **Step 4: Run to verify it passes**

Run: `python -m pytest tests/test_config.py -q`
Expected: PASS (existing config tests + 2 new).

- [ ] **Step 5: Commit**

```bash
git add broker/config.py tests/test_config.py
git commit -m "feat: config paths for ssh revocations + KRL output"
```

---

### Task 4: Broker issuance denial + wiring

**Files:**
- Modify: `broker/mcp_server.py` (`Broker.__init__`, `_grant_ssh`)
- Modify: `broker/main.py` (`build_broker`)
- Test: `tests/test_ssh_tool.py`

**Interfaces:**
- Consumes: `SshRevocationStore` (Task 1), `ssh_key_id` (Task 1), `Config.ssh_revocations_path` (Task 3).
- Produces: `Broker.__init__` gains `ssh_revocations: SshRevocationStore | None = None`; `_grant_ssh` denies a revoked pairing with the standard null shape + audit `decision="denied"` and reason `"credential revoked"`; issuance-status failures fail closed.

- [ ] **Step 1: Write the failing tests**

First extend `_make_broker` in `tests/test_ssh_tool.py` to accept revocations. Change its signature and body:

```python
from broker.ssh_revocation_store import SshRevocationStore  # add to imports


def _make_broker(tmp_path, *, policies, with_ssh=True, ca_initialized=True, revoke=None):
    cfg = Config.from_env({
        "POLICIES_PATH": _write_policies(tmp_path, policies),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTS_PATH": str(tmp_path / "agents.json"),
        "SSH_CA_PATH": str(tmp_path / "ssh_ca.json"),
        "SSH_RESOURCES_PATH": str(tmp_path / "ssh.json"),
        "SSH_REVOCATIONS_PATH": str(tmp_path / "revocations.json"),
    })
    agents = AgentStore(cfg.agents_path, "pw")
    agent_key = agents.register("claude-code")
    ssh_resources = None
    ssh_ca = None
    if with_ssh:
        ssh_resources = SshResourceStore(cfg.ssh_resources_path, "pw")
        ssh_resources.store(SshResource(
            name="web-1", host="10.0.0.5", port=22, principal="deploy",
            force_command=None, created_at="2026-07-05T10:00:00+00:00",
        ))
        ssh_ca = SshCaStore(cfg.ssh_ca_path, "pw")
        if ca_initialized:
            ssh_ca.initialize()
    revocations = SshRevocationStore(cfg.ssh_revocations_path, "pw")
    if revoke:
        agent_name, resource_name = revoke
        from broker.ssh_validation import ssh_key_id
        revocations.revoke(
            key_id=ssh_key_id(agent_name, resource_name),
            agent=agent_name, resource=resource_name,
            revoked_at="2026-07-08T00:00:00+00:00",
        )
    broker = Broker(
        config=cfg,
        store=CredentialStore(cfg.credentials_path, "pw"),
        engine=PolicyEngine.from_file(cfg.policies_path),
        audit=AuditLogger(cfg.logs_path),
        approvals=ApprovalQueue(),
        agents=agents,
        ssh_resources=ssh_resources,
        ssh_ca=ssh_ca,
        ssh_revocations=revocations,
    )
    return broker, agent_key, tmp_path / "audit.log"
```

Then add these tests to the file:

```python
async def test_revoked_key_id_denied_and_never_signs(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW, revoke=("claude-code", "web-1"))
    result = await broker.request_ssh_certificate("claude-code", key, "web-1")
    _assert_denied_shape(result)
    assert result["reason"] == "credential revoked"
    entry = json.loads(log.read_text().strip().splitlines()[-1])
    assert entry["decision"] == "denied"


async def test_non_revoked_pairing_still_grants(tmp_path):
    # Revoking a DIFFERENT resource must not block web-1.
    broker, key, _log = _make_broker(tmp_path, policies=_ALLOW, revoke=("claude-code", "other"))
    result = await broker.request_ssh_certificate("claude-code", key, "web-1")
    assert result["granted"] is True


async def test_revocation_store_failure_fails_closed(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW)

    class _Boom:
        def is_revoked(self, key_id):
            raise RuntimeError("REVOCATION_STORE_DETAIL")

    broker.ssh_revocations = _Boom()
    result = await broker.request_ssh_certificate("claude-code", key, "web-1")
    _assert_denied_shape(result)
    assert "REVOCATION_STORE_DETAIL" not in result["reason"]
    log_text = log.read_text()
    assert '"decision": "denied"' in log_text
    assert "REVOCATION_STORE_DETAIL" not in log_text
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/test_ssh_tool.py -k "revoked or revocation or non_revoked" -q`
Expected: FAIL (`Broker.__init__` has no `ssh_revocations`).

- [ ] **Step 3: Wire the broker + denial**

In `broker/mcp_server.py`:

Add the import near the other ssh imports (top of file):

```python
from broker.ssh_validation import ssh_key_id
```

Add the constructor parameter (after `ssh_ca: SshCaStore | None = None,`):

```python
        ssh_revocations: SshRevocationStore | None = None,
```

Add the attribute assignment (after `self.ssh_ca = ssh_ca`):

```python
        self.ssh_revocations = ssh_revocations
```

Add the `SshRevocationStore` import at the top (next to `from broker.ssh_ca_store import SshCaStore`):

```python
from broker.ssh_revocation_store import SshRevocationStore
```

In `_grant_ssh`, replace the current key_id composition line:

```python
        key_id = f"agentgate:{agent}:{resource}"
```

with the canonical helper + the revocation gate (placed after the CA load succeeds, before `issue_certificate`):

```python
        key_id = ssh_key_id(agent, resource)
        try:
            revoked = (
                self.ssh_revocations is not None
                and self.ssh_revocations.is_revoked(key_id)
            )
        except Exception:
            # Cannot determine revocation status -> fail closed (deny), audit,
            # leak nothing about the store internals.
            self.audit.log(
                agent=agent, credential_requested=resource, policy_matched=policy_name,
                decision="denied", mode=mode, token_expiry=None,
            )
            return self._ssh_deny("could not check revocation status")
        if revoked:
            self.audit.log(
                agent=agent, credential_requested=resource, policy_matched=policy_name,
                decision="denied", mode=mode, token_expiry=None,
            )
            return self._ssh_deny("credential revoked")
```

In `broker/main.py` `build_broker`, add to the `Broker(...)` call (after the `ssh_ca=...` line):

```python
        ssh_revocations=SshRevocationStore(config.ssh_revocations_path, master_password),
```

and add the import at the top of `main.py` (next to the other ssh store imports):

```python
from broker.ssh_revocation_store import SshRevocationStore
```

- [ ] **Step 4: Run to verify they pass**

Run: `python -m pytest tests/test_ssh_tool.py -q`
Expected: PASS (existing ssh tool tests + 3 new; the existing `test_grant_returns_key_cert_and_audits_without_private_key` still asserts `key_id == "agentgate:claude-code:web-1"`, unchanged by the helper).

- [ ] **Step 5: Commit**

```bash
git add broker/mcp_server.py broker/main.py tests/test_ssh_tool.py
git commit -m "feat: deny issuance of revoked ssh key_ids (fail-closed) + wire store"
```

---

### Task 5: CLI — `ssh-revoke` / `ssh-unrevoke` / `ssh-revoke-list` / `ssh-krl-write`

**Files:**
- Modify: `cli/commands.py`
- Test: `tests/test_ssh_cli.py`

**Interfaces:**
- Consumes: `SshRevocationStore`, `ssh_key_id`, `validate_key_id`/`SshValidationError` (Task 1); `SshKeygenKrlWriter`, `KrlWriteError` (Task 2); `SshCaStore.public_line` (existing); `Config.ssh_revocations_path` / `Config.ssh_krl_path` (Task 3).
- Produces: four operator subcommands. `ssh-revoke <agent> <resource> [--reason]`, `ssh-unrevoke <agent> <resource>`, `ssh-revoke-list`, `ssh-krl-write [path]`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_ssh_cli.py` (match the file's existing harness — it drives `cli.commands.run(argv, ...)` or `main([...])`; read the top of the file and mirror exactly how other `ssh-*` tests invoke the CLI and set `AGENTGATE_HOME`/master password). The tests below assume a helper `_run(args, tmp_path)` returning the process exit code, and that `AGENTGATE_HOME` points at `tmp_path` and the master password is provided the same way the existing ssh-add tests do it. Inject a fake KRL writer by monkeypatching `cli.commands.SshKeygenKrlWriter`.

```python
from broker.ssh_revocation_store import SshRevocationStore
from broker.ssh_validation import ssh_key_id
from broker.ssh_krl import KrlWriteError


class _FakeKrlWriter:
    calls = []

    def write_krl(self, ca_public_openssh, key_ids, out_path):
        type(self).calls.append((ca_public_openssh, list(key_ids), out_path))
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("SSHKRL-FAKE")


def test_ssh_revoke_writes_store_audits_and_generates_krl(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("cli.commands.SshKeygenKrlWriter", _FakeKrlWriter)
    _FakeKrlWriter.calls = []
    _init_ca(tmp_path)  # mirror how existing ssh-ca-init tests set up the CA
    rc = _run(["ssh-revoke", "claude-code", "web-1", "--reason", "compromised"], tmp_path)
    assert rc == 0
    store = SshRevocationStore(str(tmp_path / "ssh_revocations.json"), _MASTER)
    assert store.is_revoked(ssh_key_id("claude-code", "web-1"))
    # KRL regenerated with exactly the revoked id.
    assert _FakeKrlWriter.calls[-1][1] == [ssh_key_id("claude-code", "web-1")]
    audit = (tmp_path / "audit.log").read_text()
    assert '"action": "ssh-revoke"' in audit
    assert '"subject": "agentgate:claude-code:web-1"' in audit


def test_ssh_revoke_list_prints_metadata_only(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("cli.commands.SshKeygenKrlWriter", _FakeKrlWriter)
    _init_ca(tmp_path)
    _run(["ssh-revoke", "claude-code", "web-1"], tmp_path)
    capsys.readouterr()
    rc = _run(["ssh-revoke-list"], tmp_path)
    assert rc == 0
    out = capsys.readouterr().out
    assert "agentgate:claude-code:web-1" in out


def test_ssh_unrevoke_removes_and_audits(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("cli.commands.SshKeygenKrlWriter", _FakeKrlWriter)
    _init_ca(tmp_path)
    _run(["ssh-revoke", "claude-code", "web-1"], tmp_path)
    rc = _run(["ssh-unrevoke", "claude-code", "web-1"], tmp_path)
    assert rc == 0
    store = SshRevocationStore(str(tmp_path / "ssh_revocations.json"), _MASTER)
    assert not store.is_revoked(ssh_key_id("claude-code", "web-1"))
    assert '"action": "ssh-unrevoke"' in (tmp_path / "audit.log").read_text()


def test_ssh_unrevoke_absent_exits_1_no_audit(tmp_path, monkeypatch):
    monkeypatch.setattr("cli.commands.SshKeygenKrlWriter", _FakeKrlWriter)
    _init_ca(tmp_path)
    rc = _run(["ssh-unrevoke", "claude-code", "web-1"], tmp_path)
    assert rc == 1
    audit = tmp_path / "audit.log"
    assert not audit.exists() or '"action": "ssh-unrevoke"' not in audit.read_text()


def test_ssh_revoke_invalid_agent_exits_2_no_write(tmp_path, monkeypatch):
    monkeypatch.setattr("cli.commands.SshKeygenKrlWriter", _FakeKrlWriter)
    _init_ca(tmp_path)
    rc = _run(["ssh-revoke", "bad agent\n", "web-1"], tmp_path)
    assert rc == 2
    store = SshRevocationStore(str(tmp_path / "ssh_revocations.json"), _MASTER)
    assert store.revoked_key_ids() == []


def test_ssh_revoke_krl_failure_exits_1_but_store_updated(tmp_path, monkeypatch):
    class _BoomWriter:
        def write_krl(self, *a, **k):
            raise KrlWriteError("failed to generate KRL")
    monkeypatch.setattr("cli.commands.SshKeygenKrlWriter", _BoomWriter)
    _init_ca(tmp_path)
    rc = _run(["ssh-revoke", "claude-code", "web-1"], tmp_path)
    assert rc == 1
    # Revocation is NOT lost — broker-layer denial already protects issuance.
    store = SshRevocationStore(str(tmp_path / "ssh_revocations.json"), _MASTER)
    assert store.is_revoked(ssh_key_id("claude-code", "web-1"))
```

Implementer note: `_run`, `_MASTER`, and `_init_ca` are whatever the existing `tests/test_ssh_cli.py` already uses to invoke the CLI, supply the master password, and create the CA. Reuse the file's existing helpers rather than inventing new ones; the snippets above only show the assertions unique to revocation. If the file has no `_init_ca`, inline `_run(["ssh-ca-init"], tmp_path)`.

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/test_ssh_cli.py -k "revoke or unrevoke" -q`
Expected: FAIL (unrecognized arguments: `ssh-revoke`).

- [ ] **Step 3: Implement the CLI**

In `cli/commands.py`, add imports near the other ssh imports:

```python
from broker.ssh_revocation_store import SshRevocationStore
from broker.ssh_krl import KrlWriteError, SshKeygenKrlWriter
from broker.ssh_validation import ssh_key_id
```

(Existing imports already provide `validate_principal`, `SshValidationError`, `SshCaStore`.)

Register the subcommands in the argparse section (after the `ssh-remove` parser, ~line 73):

```python
    rv = sub.add_parser("ssh-revoke", help="revoke an agent's certs for a resource")
    rv.add_argument("agent")
    rv.add_argument("resource")
    rv.add_argument("--reason", default=None, help="operator note stored with the revocation")
    ur = sub.add_parser("ssh-unrevoke", help="lift a revocation")
    ur.add_argument("agent")
    ur.add_argument("resource")
    sub.add_parser("ssh-revoke-list", help="list revoked certs (metadata only)")
    kw = sub.add_parser("ssh-krl-write", help="regenerate the KRL file")
    kw.add_argument("path", nargs="?", default=None, help="output path (default: configured ssh_krl_path)")
```

Add a shared KRL-regeneration helper (near the other module-level `_` helpers in `cli/commands.py`). It constructs `SshKeygenKrlWriter` by name so tests can monkeypatch it:

```python
def _regenerate_krl(config, master_password, out_path=None):
    """Load the CA public key + all revoked key_ids and (re)write the KRL.
    Raises KrlWriteError / KeyError on failure; callers decide the exit code."""
    ca = SshCaStore(config.ssh_ca_path, _password(master_password))
    public_line = ca.public_line()  # KeyError if CA not initialized
    revocations = SshRevocationStore(config.ssh_revocations_path, _password(master_password))
    target = out_path or config.ssh_krl_path
    SshKeygenKrlWriter().write_krl(public_line, revocations.revoked_key_ids(), target)
    return target
```

Add the command handlers (after the `ssh-remove` block, ~line 323):

```python
    if args.command == "ssh-revoke":
        try:
            agent = validate_principal_free(args.agent)
            resource = validate_principal_free(args.resource)
            reason = _validate_reason(args.reason)
        except SshValidationError as exc:
            print(f"invalid revocation: {exc}", file=sys.stderr)
            return 2
        key_id = ssh_key_id(agent, resource)
        store = SshRevocationStore(config.ssh_revocations_path, _password(master_password))
        store.revoke(
            key_id=key_id, agent=agent, resource=resource,
            revoked_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            reason=reason,
        )
        AuditLogger(config.logs_path).log_operator(action="ssh-revoke", subject=key_id)
        try:
            path = _regenerate_krl(config, master_password)
        except KeyError:
            print("revoked, but ssh CA not initialized so no KRL was written "
                  "(run ssh-ca-init)", file=sys.stderr)
            return 1
        except KrlWriteError:
            print("revoked, but KRL generation failed; retry with ssh-krl-write",
                  file=sys.stderr)
            return 1
        print(f"revoked {key_id}")
        print(f"KRL written to {path} — deploy it to each server's RevokedKeys")
        return 0

    if args.command == "ssh-unrevoke":
        try:
            agent = validate_principal_free(args.agent)
            resource = validate_principal_free(args.resource)
        except SshValidationError as exc:
            print(f"invalid revocation: {exc}", file=sys.stderr)
            return 2
        key_id = ssh_key_id(agent, resource)
        store = SshRevocationStore(config.ssh_revocations_path, _password(master_password))
        if not store.unrevoke(key_id):
            print(f"{key_id} was not revoked", file=sys.stderr)
            return 1
        AuditLogger(config.logs_path).log_operator(action="ssh-unrevoke", subject=key_id)
        try:
            path = _regenerate_krl(config, master_password)
        except (KeyError, KrlWriteError):
            print("unrevoked, but KRL regeneration failed; retry with ssh-krl-write",
                  file=sys.stderr)
            return 1
        print(f"unrevoked {key_id}; KRL rewritten to {path}")
        return 0

    if args.command == "ssh-revoke-list":
        store = SshRevocationStore(config.ssh_revocations_path, _password(master_password))
        for e in store.list_entries():
            reason = f"  ({e['reason']})" if e["reason"] else ""
            print(f"{e['key_id']}  revoked {e['revoked_at']}{reason}")
        return 0

    if args.command == "ssh-krl-write":
        try:
            path = _regenerate_krl(config, master_password, out_path=args.path)
        except KeyError:
            print("ssh CA not initialized (run ssh-ca-init first)", file=sys.stderr)
            return 1
        except KrlWriteError:
            print("KRL generation failed", file=sys.stderr)
            return 1
        print(f"KRL written to {path}")
        return 0
```

This needs two small validators. The agent/resource strings are NOT POSIX principals (agent names can contain e.g. hyphens/dots beyond the principal charset), so validate them as "non-empty printable, no injection" — reuse the `key_id` rule. Add near the top-of-function or as module helpers:

```python
def validate_principal_free(raw):
    # Agent + resource names embedded into a key_id: must be non-empty
    # printable single-line text (same rule validate_key_id enforces on the
    # composed id). Rejects the newline/control chars that would let a name
    # smuggle a KRL directive.
    from broker.ssh_validation import validate_key_id, SshValidationError
    if not isinstance(raw, str) or ":" in raw:
        raise SshValidationError("name must not contain ':'")
    validate_key_id(raw)  # printable / non-empty gate
    return raw


def _validate_reason(raw):
    from broker.ssh_validation import SshValidationError
    if raw is None:
        return None
    if not raw.isprintable():
        raise SshValidationError("reason must be printable text")
    return raw
```

Rationale for the `":"` guard: the key_id is colon-delimited (`agentgate:agent:resource`); forbidding `:` in the parts keeps the composed id unambiguous and parseable in audit/logs. Place `validate_principal_free`/`_validate_reason` as module-level functions in `cli/commands.py` (not inside `run`).

- [ ] **Step 4: Run to verify they pass**

Run: `python -m pytest tests/test_ssh_cli.py -q`
Expected: PASS (existing ssh CLI tests + 6 new).

- [ ] **Step 5: Commit**

```bash
git add cli/commands.py tests/test_ssh_cli.py
git commit -m "feat: ssh-revoke/unrevoke/revoke-list/krl-write CLI commands"
```

---

### Task 6: Docs + skip-gated integration test

**Files:**
- Modify: `README.md`
- Create: `tests/test_ssh_krl_integration.py`

**Interfaces:**
- Consumes: everything above; `broker.ssh_ca.generate_ca` + `issue_certificate` (existing) to mint a real cert to test against.

- [ ] **Step 1: Write the skip-gated integration test**

Create `tests/test_ssh_krl_integration.py`:

```python
from __future__ import annotations

import shutil
import subprocess

import pytest

from broker.ssh_ca import generate_ca, issue_certificate
from broker.ssh_krl import SshKeygenKrlWriter
from broker.ssh_validation import ssh_key_id

pytestmark = pytest.mark.skipif(
    shutil.which("ssh-keygen") is None,
    reason="ssh-keygen not installed; real KRL generation is untestable here",
)


def _write(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def test_real_krl_marks_revoked_cert_revoked(tmp_path):
    ca = generate_ca()
    ca_pub = str(tmp_path / "ca.pub")
    _write(ca_pub, ca.public_key_openssh + "\n")

    revoked_kid = ssh_key_id("claude-code", "web-1")
    ok_kid = ssh_key_id("claude-code", "db-1")

    def _cert_file(kid):
        cred = issue_certificate(ca.private_key_pem, key_id=kid, principal="deploy",
                                 ttl_minutes=15)
        p = str(tmp_path / (kid.replace(":", "_") + "-cert.pub"))
        _write(p, cred.certificate + "\n")
        return p

    revoked_cert = _cert_file(revoked_kid)
    ok_cert = _cert_file(ok_kid)

    krl = str(tmp_path / "krl")
    SshKeygenKrlWriter().write_krl(ca.public_key_openssh, [revoked_kid], krl)

    # ssh-keygen -Q -f <krl> <cert> exits non-zero if the cert is revoked.
    revoked_rc = subprocess.run(["ssh-keygen", "-Q", "-f", krl, revoked_cert],
                                capture_output=True).returncode
    ok_rc = subprocess.run(["ssh-keygen", "-Q", "-f", krl, ok_cert],
                           capture_output=True).returncode
    assert revoked_rc != 0, "revoked cert should be reported revoked"
    assert ok_rc == 0, "non-revoked cert should pass"
```

Implementer note: if the installed `ssh-keygen` uses different `-Q` semantics (very old builds print a message and return 0), fall back to asserting on captured stdout containing "revoked" for `revoked_cert` and not for `ok_cert`. Verify the exact behavior of the local `ssh-keygen` first (`ssh-keygen -Q -f <krl> <cert>; echo $?`) and pick whichever signal (exit code or stdout marker) that build actually provides — keep both certs in the test either way.

- [ ] **Step 2: Run the integration test**

Run: `python -m pytest tests/test_ssh_krl_integration.py -q`
Expected: PASS if `ssh-keygen` is installed, otherwise SKIP. Adjust the assertion per the implementer note if the local build's `-Q` differs.

- [ ] **Step 3: Update the README**

Read the existing `## SSH Broker` section of `README.md`. After the certificate-issuance description, add a subsection (match surrounding heading depth and prose style):

```markdown
### Revoking a certificate

AgentGate certificates are short-lived (default 15 min), but you can revoke one
before it expires. Revocation is enforced at two layers:

- **Broker layer:** `agentgate ssh-revoke <agent> <resource>` immediately stops
  the broker from minting new certificates for that agent on that resource.
- **Server layer:** the same command regenerates an OpenSSH **KRL** (Key
  Revocation List) at the configured `ssh_krl_path`. Deploy it to each server
  and reference it from `sshd_config`, exactly as you already distribute the CA
  public key:

  ```
  RevokedKeys /etc/ssh/agentgate_krl
  ```

  sshd then rejects any presented certificate whose key_id is revoked,
  regardless of remaining validity.

Commands:

- `agentgate ssh-revoke <agent> <resource> [--reason TEXT]` — revoke and rewrite the KRL.
- `agentgate ssh-unrevoke <agent> <resource>` — lift a revocation and rewrite the KRL.
- `agentgate ssh-revoke-list` — list revoked certificates (metadata only).
- `agentgate ssh-krl-write [path]` — regenerate the KRL on demand (e.g. after a failed write).

Revocation requires the OpenSSH `ssh-keygen` binary on the broker host (used to
generate the KRL). The broker generates the KRL; distributing it to servers is
out of band, the same trust model as `TrustedUserCAKeys`.
```

If the README has a tool-count line or feature list, confirm it still reads **9 MCP tools** (revocation adds no agent-facing tool) and update any "N CLI commands" count to include the four new ones.

- [ ] **Step 4: Run the full suite**

Run: `python -m pytest -q`
Expected: PASS — all prior tests plus the new revocation-store, KRL, config, broker, and CLI tests; the integration test passes or skips.

- [ ] **Step 5: Commit**

```bash
git add README.md tests/test_ssh_krl_integration.py
git commit -m "docs: SSH revocation section + skip-gated real-KRL integration test"
```

---

## Self-Review

**1. Spec coverage:**
- Two enforcement layers → Task 4 (broker denial) + Tasks 2/5 (KRL) ✓
- Revoke by key_id, no issuance tracking → `ssh_key_id` helper, store keyed by key_id ✓
- `ssh-keygen -k` behind injectable seam, Fake for unit tests → Task 2 (`SshKeygenKrlWriter` with `_runner`), Task 5 (`_FakeKrlWriter` monkeypatched) ✓
- `SshRevocationStore` encrypted-at-rest → Task 1 (`crypto.encrypt` per record; disk-plaintext test) ✓
- Spec-file injection barrier (validate at sink) → Task 2 (`validate_key_id` before spec write; injection test) ✓
- Generic error on subprocess failure, no path leak → Task 2 (`KrlWriteError`; leak test) ✓
- Fail-closed ordering (store+audit before KRL; store retained on KRL failure) → Task 5 (`ssh-revoke` handler; `test_ssh_revoke_krl_failure_exits_1_but_store_updated`) ✓
- Fail-closed on unknown revocation status → Task 4 (`could not check revocation status`) ✓
- CLI exits: invalid → 2, unrevoke-absent → 1, KRL failure → 1 → Task 5 tests ✓
- Config paths anchored to AGENTGATE_HOME → Task 3 ✓
- No new MCP tool; 9 tools → Task 6 README check ✓
- Skip-gated real-ssh-keygen integration test → Task 6 ✓
- Operator-only, CA private key never in KRL path → Task 2 (public key only), Task 5 (operator CLI) ✓

**2. Placeholder scan:** No TBD/TODO. Every code step has complete code. The only deferred specifics are the reuse of `tests/test_ssh_cli.py`'s existing `_run`/`_MASTER`/`_init_ca` harness (explicitly flagged as "reuse the file's existing helpers") and the `-Q` behavior fallback (flagged with a concrete verification step) — both are integration points with existing code, not placeholders in the logic.

**3. Type consistency:**
- `ssh_key_id(agent, resource) -> str` used identically in Tasks 1, 4, 5 ✓
- `SshRevocationStore.revoke(*, key_id, agent, resource, revoked_at, reason=None)` — same kwargs in Tasks 1, 4, 5 ✓
- `SshRevocationStore.is_revoked/unrevoke/revoked_key_ids/list_entries` — consistent across Tasks 1, 4, 5 ✓
- `KrlWriter.write_krl(ca_public_openssh, key_ids, out_path)` — same signature in Task 2 def, Task 5 `_FakeKrlWriter`/`_regenerate_krl`, Task 6 integration test ✓
- `KrlWriteError` raised in Task 2, caught in Task 5 ✓
- `Config.ssh_revocations_path` / `ssh_krl_path` — defined Task 3, consumed Tasks 4, 5 ✓
```
