# AgentGate SSH Broker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Agents get short-lived, principal-pinned SSH access to registered servers via CA-signed ephemeral Ed25519 user certificates — never a standing key.

**Architecture:** AgentGate becomes an SSH CA (private key encrypted at rest via EncryptedStore). Operators enroll servers once with `TrustedUserCAKeys`; on `ssh_certificate_request` the broker generates a fresh keypair and signs a certificate (principal + optional force-command from the operator-registered resource, TTL-bounded validity). sshd enforces expiry natively — no reaper. Auth/policy/escalation/audit spine reused unchanged.

**Tech Stack:** Python 3.11+, `cryptography` (already a dependency, ≥42; `SSHCertificateBuilder` verified on 49.0.0 — NO new dependencies), fastmcp, pytest (`asyncio_mode = auto`: async tests need no decorator).

## Global Constraints

- The generated private key appears ONLY in the tool response — never in audit records, logs, error messages, `reason` strings, or dataclass `repr` (use `field(repr=False)`).
- The CA private key is encrypted at rest (Argon2id + AES-256-GCM via `EncryptedStore`/`crypto`), never printed, never in argv.
- Every denial path writes an audited `decision="denied"` (or `"expired"`) row AND returns the full null-field response shape `{granted: false, host: null, port: null, username: null, private_key: null, certificate: null, expires_at: null, reason}`.
- Authentication strictly precedes escalation — an unknown agent must never create a pending approval, even in MANUAL mode.
- Validate at input AND at the signing sink: principal must fullmatch `[a-z_][a-z0-9_-]{0,31}`; force-command non-empty and `str.isprintable()`; key_id non-empty and printable. Canonical patterns live ONLY in `broker/ssh_validation.py` (leaf module — the `broker/role_naming.py` discipline). Always `.fullmatch`, never `.match`.
- Certificate hardening is fixed, not configurable: extensions exactly `{permit-pty: ""}` (no agent-/port-/X11-forwarding, no user-rc); type USER; single principal; `key_id = "agentgate:<agent>:<resource>"`; serial = `secrets.randbits(63)`.
- MCP tool name is exactly `ssh_certificate_request` (underscores). Tool count becomes 8; grant-or-change count becomes 5.
- `SSH_CERT_TTL_MINUTES` default 15, integer ≥ 1. Exception messages from stores/signing never reach an agent-visible `reason`.
- Commit messages follow the existing `feat:`/`fix:`/`docs:` convention. All commits end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

---

### Task 1: `broker/ssh_validation.py` — leaf validation module

**Files:**
- Create: `broker/ssh_validation.py`
- Test: `tests/test_ssh_validation.py`

**Interfaces:**
- Consumes: nothing (leaf module; imports only `re`).
- Produces: `SshValidationError(ValueError)`; `PRINCIPAL_RE` (compiled, unanchored — use with `.fullmatch`); `validate_principal(raw) -> str`; `validate_force_command(raw) -> str`; `validate_key_id(raw) -> str`. Tasks 2 and 6 import these.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_ssh_validation.py
from __future__ import annotations

import pytest

from broker.ssh_validation import (
    PRINCIPAL_RE,
    SshValidationError,
    validate_force_command,
    validate_key_id,
    validate_principal,
)


def test_valid_principals_pass():
    assert validate_principal("deploy") == "deploy"
    assert validate_principal("_svc") == "_svc"
    assert validate_principal("web-app_2") == "web-app_2"
    assert validate_principal("a" * 32) == "a" * 32  # 32 chars max


@pytest.mark.parametrize("bad", [
    "", "Root", "1abc", "deploy\n", "deploy user", "a" * 33,
    "deploy;rm", "-flag", "usr$", 42, None,
])
def test_invalid_principals_raise(bad):
    with pytest.raises(SshValidationError):
        validate_principal(bad)


def test_principal_re_is_fullmatch_safe_against_trailing_newline():
    # Unanchored on purpose; every caller must use .fullmatch.
    assert PRINCIPAL_RE.fullmatch("deploy")
    assert not PRINCIPAL_RE.fullmatch("deploy\n")


def test_valid_force_commands_pass():
    assert validate_force_command("systemctl restart myapp") == "systemctl restart myapp"
    assert validate_force_command("echo ok") == "echo ok"


@pytest.mark.parametrize("bad", ["", "echo hi\n", "echo\rhi", "echo \x00 hi", "a\tb", 42, None])
def test_invalid_force_commands_raise(bad):
    # isprintable() rejects NUL/newline/CR/tab and other control chars.
    with pytest.raises(SshValidationError):
        validate_force_command(bad)


def test_valid_key_ids_pass():
    assert validate_key_id("agentgate:claude-code:web-1") == "agentgate:claude-code:web-1"


@pytest.mark.parametrize("bad", ["", "x\ny", "x\ry", "x\x00y", 42, None])
def test_invalid_key_ids_raise(bad):
    with pytest.raises(SshValidationError):
        validate_key_id(bad)


def test_error_is_a_valueerror():
    assert issubclass(SshValidationError, ValueError)
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_ssh_validation.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'broker.ssh_validation'`.

- [ ] **Step 3: Implement**

```python
# broker/ssh_validation.py
from __future__ import annotations

import re

# Canonical validation for values that end up inside SSH certificates.
#
# This is the SINGLE SOURCE OF TRUTH for the principal pattern and the
# force-command/key_id rules, enforced both at operator input (`ssh-add`)
# and again at the signing sink (broker/ssh_ca.py) — the same
# validate-at-input-AND-sink discipline as db_grants. It lives in a leaf
# module (imports nothing from broker) so the two enforcement points can
# never drift onto divergent rules. ALWAYS match with `.fullmatch` (the
# pattern is deliberately unanchored; `.match` would admit a trailing
# newline).

# POSIX username: lowercase letter or underscore, then up to 31 of
# [a-z0-9_-]. 32 chars total max.
PRINCIPAL_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}")


class SshValidationError(ValueError):
    """Raised when a principal, force-command, or key_id is unsafe."""


def validate_principal(raw: object) -> str:
    if not isinstance(raw, str) or not PRINCIPAL_RE.fullmatch(raw):
        raise SshValidationError(f"invalid principal {raw!r}")
    return raw


def validate_force_command(raw: object) -> str:
    # isprintable() is False for NUL, newline, CR, tab, and all control
    # characters — anything that could smuggle a second directive into the
    # certificate's critical option.
    if not isinstance(raw, str) or not raw or not raw.isprintable():
        raise SshValidationError("force-command must be non-empty printable text")
    return raw


def validate_key_id(raw: object) -> str:
    # key_id is free text that lands in the target server's sshd log lines;
    # keep it one printable line so it cannot forge log entries.
    if not isinstance(raw, str) or not raw or not raw.isprintable():
        raise SshValidationError("key_id must be non-empty printable text")
    return raw
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_ssh_validation.py -q`
Expected: PASS (all tests).

- [ ] **Step 5: Commit**

```bash
git add broker/ssh_validation.py tests/test_ssh_validation.py
git commit -m "feat: ssh validation leaf module (principal/force-command/key_id rules)"
```

---

### Task 2: `broker/ssh_ca.py` — keygen + certificate signing

**Files:**
- Create: `broker/ssh_ca.py`
- Test: `tests/test_ssh_ca.py`

**Interfaces:**
- Consumes: `broker.ssh_validation.validate_principal/validate_force_command/validate_key_id` (Task 1).
- Produces: `SshKeypair(private_key_pem, public_key_openssh)` (private repr-suppressed); `IssuedCredential(private_key, certificate, expires_at)` (private repr-suppressed); `generate_ca() -> SshKeypair`; `generate_keypair() -> SshKeypair`; `issue_certificate(ca_private_key_pem, *, key_id, principal, ttl_minutes, force_command=None) -> IssuedCredential`. Tasks 3 and 5 consume these.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_ssh_ca.py
from __future__ import annotations

import datetime
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization.ssh import (
    SSHCertificateType,
    load_ssh_public_identity,
)

from broker.ssh_ca import IssuedCredential, generate_ca, generate_keypair, issue_certificate
from broker.ssh_validation import SshValidationError


def test_generate_ca_produces_openssh_ed25519_pair():
    ca = generate_ca()
    assert ca.private_key_pem.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert ca.public_key_openssh.startswith("ssh-ed25519 ")
    # Loadable by the cryptography lib (what signing will do).
    serialization.load_ssh_private_key(ca.private_key_pem.encode(), password=None)


def test_keypairs_are_distinct_per_call():
    assert generate_keypair().public_key_openssh != generate_keypair().public_key_openssh


def test_private_key_never_in_repr():
    ca = generate_ca()
    assert "PRIVATE KEY" not in repr(ca)
    cred = issue_certificate(
        ca.private_key_pem, key_id="agentgate:cc:web-1", principal="deploy", ttl_minutes=15,
    )
    assert "PRIVATE KEY" not in repr(cred)


def test_issued_certificate_contents():
    ca = generate_ca()
    before = int(time.time())
    cred = issue_certificate(
        ca.private_key_pem, key_id="agentgate:cc:web-1", principal="deploy", ttl_minutes=15,
    )
    after = int(time.time())

    assert cred.private_key.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    cert = load_ssh_public_identity(cred.certificate.encode())
    cert.verify_cert_signature()  # self-consistent signature
    # Signed by OUR ca, not some other key.
    ca_pub = serialization.load_ssh_public_key(ca.public_key_openssh.encode())
    assert cert.signature_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ) == ca_pub.public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    assert cert.type == SSHCertificateType.USER
    assert cert.key_id == b"agentgate:cc:web-1"
    assert cert.valid_principals == [b"deploy"]
    assert before <= cert.valid_after <= after
    assert cert.valid_before == cert.valid_after + 15 * 60
    # Hardening: permit-pty only, nothing else; no force-command unless configured.
    assert cert.extensions == {b"permit-pty": b""}
    assert cert.critical_options == {}
    assert cert.serial > 0
    # expires_at is UTC ISO and matches the cert's own validity end.
    parsed = datetime.datetime.fromisoformat(cred.expires_at)
    assert int(parsed.timestamp()) == cert.valid_before


def test_force_command_lands_in_critical_options():
    ca = generate_ca()
    cred = issue_certificate(
        ca.private_key_pem, key_id="agentgate:cc:web-1", principal="deploy",
        ttl_minutes=15, force_command="echo ok",
    )
    cert = load_ssh_public_identity(cred.certificate.encode())
    assert cert.critical_options == {b"force-command": b"echo ok"}


def test_serials_and_keys_differ_across_grants():
    ca = generate_ca()
    a = issue_certificate(ca.private_key_pem, key_id="k", principal="deploy", ttl_minutes=15)
    b = issue_certificate(ca.private_key_pem, key_id="k", principal="deploy", ttl_minutes=15)
    assert a.private_key != b.private_key
    ca_cert = load_ssh_public_identity(a.certificate.encode())
    cb_cert = load_ssh_public_identity(b.certificate.encode())
    assert ca_cert.serial != cb_cert.serial


def test_sink_revalidates_principal_force_command_and_key_id():
    ca = generate_ca()
    with pytest.raises(SshValidationError):
        issue_certificate(ca.private_key_pem, key_id="k", principal="Root", ttl_minutes=15)
    with pytest.raises(SshValidationError):
        issue_certificate(ca.private_key_pem, key_id="k", principal="deploy\n", ttl_minutes=15)
    with pytest.raises(SshValidationError):
        issue_certificate(
            ca.private_key_pem, key_id="k", principal="deploy",
            ttl_minutes=15, force_command="echo hi\nrm -rf /",
        )
    with pytest.raises(SshValidationError):
        issue_certificate(ca.private_key_pem, key_id="k\nfake", principal="deploy", ttl_minutes=15)


def test_ttl_must_be_positive():
    ca = generate_ca()
    with pytest.raises(ValueError):
        issue_certificate(ca.private_key_pem, key_id="k", principal="deploy", ttl_minutes=0)
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_ssh_ca.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'broker.ssh_ca'`.

- [ ] **Step 3: Implement**

```python
# broker/ssh_ca.py
from __future__ import annotations

import datetime
import secrets
import time

from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization.ssh import (
    SSHCertificateBuilder,
    SSHCertificateType,
)

from broker.ssh_validation import (
    validate_force_command,
    validate_key_id,
    validate_principal,
)


@dataclass(frozen=True)
class SshKeypair:
    # repr=False: this PEM is a cleartext private key; a stray repr()/log
    # of the dataclass must never expose it.
    private_key_pem: str = field(repr=False)
    public_key_openssh: str


@dataclass(frozen=True)
class IssuedCredential:
    private_key: str = field(repr=False)
    certificate: str
    expires_at: str


def _new_ed25519() -> SshKeypair:
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode()
    pub = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode()
    return SshKeypair(private_key_pem=pem, public_key_openssh=pub)


def generate_ca() -> SshKeypair:
    return _new_ed25519()


def generate_keypair() -> SshKeypair:
    return _new_ed25519()


def issue_certificate(
    ca_private_key_pem: str,
    *,
    key_id: str,
    principal: str,
    ttl_minutes: int,
    force_command: str | None = None,
) -> IssuedCredential:
    """Generate a fresh keypair and sign a hardened user certificate.

    Sink re-validation: principal, force-command, and key_id are checked
    here regardless of what the caller already validated — no unvetted
    value may reach a certificate field (the db_grants discipline).
    Extensions are fixed to permit-pty only: no agent/port/X11 forwarding,
    no user-rc, and never configurable from a request.
    """
    principal = validate_principal(principal)
    key_id = validate_key_id(key_id)
    if force_command is not None:
        force_command = validate_force_command(force_command)
    if ttl_minutes < 1:
        raise ValueError("ttl_minutes must be >= 1")

    ca_key = serialization.load_ssh_private_key(ca_private_key_pem.encode(), password=None)
    user = _new_ed25519()
    user_pub = serialization.load_ssh_public_key(user.public_key_openssh.encode())

    valid_after = int(time.time())
    valid_before = valid_after + ttl_minutes * 60

    builder = (
        SSHCertificateBuilder()
        .public_key(user_pub)
        .serial(secrets.randbits(63))
        .type(SSHCertificateType.USER)
        .key_id(key_id.encode())
        .valid_principals([principal.encode()])
        .valid_after(valid_after)
        .valid_before(valid_before)
        .add_extension(b"permit-pty", b"")
    )
    if force_command is not None:
        builder = builder.add_critical_option(b"force-command", force_command.encode())
    cert = builder.sign(ca_key)

    expires_at = datetime.datetime.fromtimestamp(
        valid_before, tz=datetime.timezone.utc
    ).isoformat(timespec="seconds")
    return IssuedCredential(
        private_key=user.private_key_pem,
        certificate=cert.public_bytes().decode(),
        expires_at=expires_at,
    )
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_ssh_ca.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add broker/ssh_ca.py tests/test_ssh_ca.py
git commit -m "feat: ssh CA keygen + hardened certificate signing (sink-revalidated)"
```

---

### Task 3: CA store + resource store

**Files:**
- Create: `broker/ssh_ca_store.py`, `broker/ssh_resource_store.py`
- Test: `tests/test_ssh_ca_store.py`, `tests/test_ssh_resource_store.py`

**Interfaces:**
- Consumes: `broker.encrypted_store.EncryptedStore`, `broker.crypto.encrypt/decrypt`, `broker.ssh_ca.generate_ca` (Task 2).
- Produces:
  - `SshCaExistsError(Exception)`; `SshCaStore(path, master_password)` with `initialize() -> str` (returns the public line; raises `SshCaExistsError` if a CA exists), `load_private_pem() -> str` (raises `KeyError` if absent), `public_line() -> str` (raises `KeyError` if absent), `is_initialized() -> bool`.
  - `SshResource(name, host, port, principal, force_command, created_at)` (frozen dataclass; `force_command: str | None`); `SshResourceStore(path, master_password)` with `store/get/delete/list_names/list_metadata` — same contracts as `DbResourceStore` (get/delete raise `KeyError` on unknown name).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_ssh_ca_store.py
from __future__ import annotations

import json

import pytest

from broker.ssh_ca_store import SshCaExistsError, SshCaStore


def test_initialize_returns_public_line_and_persists(tmp_path):
    store = SshCaStore(str(tmp_path / "ca.json"), "pw")
    pub = store.initialize()
    assert pub.startswith("ssh-ed25519 ")
    assert store.is_initialized()
    assert store.public_line() == pub
    pem = store.load_private_pem()
    assert pem.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    # A second store instance (fresh process) sees the same CA.
    again = SshCaStore(str(tmp_path / "ca.json"), "pw")
    assert again.load_private_pem() == pem


def test_private_key_is_encrypted_on_disk(tmp_path):
    path = tmp_path / "ca.json"
    SshCaStore(str(path), "pw").initialize()
    raw = path.read_text()
    assert "PRIVATE KEY" not in raw  # ciphertext only
    assert "ssh-ed25519 " in raw     # public line stays readable


def test_initialize_twice_refuses(tmp_path):
    store = SshCaStore(str(tmp_path / "ca.json"), "pw")
    store.initialize()
    with pytest.raises(SshCaExistsError):
        store.initialize()


def test_load_before_initialize_raises_keyerror(tmp_path):
    store = SshCaStore(str(tmp_path / "ca.json"), "pw")
    assert not store.is_initialized()
    with pytest.raises(KeyError):
        store.load_private_pem()
    with pytest.raises(KeyError):
        store.public_line()
```

```python
# tests/test_ssh_resource_store.py
from __future__ import annotations

import pytest

from broker.ssh_resource_store import SshResource, SshResourceStore


def _res(name="web-1", force_command=None):
    return SshResource(
        name=name, host="10.0.0.5", port=22, principal="deploy",
        force_command=force_command, created_at="2026-07-05T10:00:00+00:00",
    )


def test_store_get_roundtrip(tmp_path):
    store = SshResourceStore(str(tmp_path / "ssh.json"), "pw")
    store.store(_res(force_command="echo ok"))
    got = store.get("web-1")
    assert got == _res(force_command="echo ok")


def test_get_unknown_raises_keyerror(tmp_path):
    store = SshResourceStore(str(tmp_path / "ssh.json"), "pw")
    with pytest.raises(KeyError):
        store.get("nope")


def test_delete_and_list_names(tmp_path):
    store = SshResourceStore(str(tmp_path / "ssh.json"), "pw")
    store.store(_res("b")); store.store(_res("a"))
    assert store.list_names() == ["a", "b"]
    store.delete("a")
    assert store.list_names() == ["b"]
    with pytest.raises(KeyError):
        store.delete("a")


def test_list_metadata_includes_everything(tmp_path):
    # Nothing in an SshResource is secret; metadata is the full record.
    store = SshResourceStore(str(tmp_path / "ssh.json"), "pw")
    store.store(_res(force_command="echo ok"))
    (meta,) = store.list_metadata()
    assert meta == {
        "name": "web-1", "host": "10.0.0.5", "port": 22, "principal": "deploy",
        "force_command": "echo ok", "created_at": "2026-07-05T10:00:00+00:00",
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_ssh_ca_store.py tests/test_ssh_resource_store.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Implement**

```python
# broker/ssh_ca_store.py
from __future__ import annotations

import datetime

from broker import crypto
from broker.encrypted_store import EncryptedStore
from broker.ssh_ca import generate_ca


class SshCaExistsError(Exception):
    """Raised when initialize() would overwrite an existing CA. Re-keying
    every enrolled server's trust must be deliberate, never accidental."""


class SshCaStore(EncryptedStore):
    """Holds the single SSH CA keypair: private key encrypted at rest,
    public line stored readable (it is public material operators paste
    into sshd_config)."""

    _SECTION = "ssh_ca"
    _KEY = "ca"

    def initialize(self) -> str:
        entries = self._entries()
        if self._KEY in entries:
            raise SshCaExistsError("ssh CA already initialized")
        ca = generate_ca()
        entries[self._KEY] = {
            "private_pem": crypto.encrypt(self._key, ca.private_key_pem),
            "public_line": ca.public_key_openssh,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(
                timespec="seconds"
            ),
        }
        self._write(self._data)
        return ca.public_key_openssh

    def is_initialized(self) -> bool:
        return self._KEY in self._entries()

    def load_private_pem(self) -> str:
        entries = self._entries()
        if self._KEY not in entries:
            raise KeyError("ssh CA not initialized")
        return crypto.decrypt(self._key, entries[self._KEY]["private_pem"])

    def public_line(self) -> str:
        entries = self._entries()
        if self._KEY not in entries:
            raise KeyError("ssh CA not initialized")
        return entries[self._KEY]["public_line"]
```

```python
# broker/ssh_resource_store.py
from __future__ import annotations

from dataclasses import dataclass

from broker.encrypted_store import EncryptedStore


@dataclass(frozen=True)
class SshResource:
    name: str
    host: str
    port: int
    principal: str
    force_command: str | None
    created_at: str


class SshResourceStore(EncryptedStore):
    """Registered SSH server resources. Nothing in a resource is secret
    (the CA key lives in SshCaStore) — subclassing EncryptedStore buys the
    0600 perms, atomic writes, and per-access disk re-read, not encryption."""

    _SECTION = "ssh_resources"

    def store(self, resource: SshResource) -> None:
        self._entries()[resource.name] = {
            "host": resource.host,
            "port": resource.port,
            "principal": resource.principal,
            "force_command": resource.force_command,
            "created_at": resource.created_at,
        }
        self._write(self._data)

    def get(self, name: str) -> SshResource:
        entries = self._entries()
        if name not in entries:
            raise KeyError(name)
        rec = entries[name]
        return SshResource(
            name=name,
            host=rec["host"],
            port=rec["port"],
            principal=rec["principal"],
            force_command=rec["force_command"],
            created_at=rec["created_at"],
        )

    def delete(self, name: str) -> None:
        entries = self._entries()
        if name not in entries:
            raise KeyError(name)
        del entries[name]
        self._write(self._data)

    def list_names(self) -> list[str]:
        return sorted(self._entries().keys())

    def list_metadata(self) -> list[dict]:
        return [
            {"name": name, **rec}
            for name, rec in sorted(self._entries().items())
        ]
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_ssh_ca_store.py tests/test_ssh_resource_store.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add broker/ssh_ca_store.py broker/ssh_resource_store.py tests/test_ssh_ca_store.py tests/test_ssh_resource_store.py
git commit -m "feat: encrypted SSH CA store + ssh resource store"
```

---

### Task 4: Config additions

**Files:**
- Modify: `broker/config.py`
- Test: `tests/test_config.py` (append)

**Interfaces:**
- Consumes: existing `_DEFAULTS`, `_default_paths`, `_require_non_empty`, `_require_int`.
- Produces: `Config.ssh_ca_path: str`, `Config.ssh_resources_path: str`, `Config.ssh_cert_ttl_minutes: int = 15` — read from `SSH_CA_PATH`, `SSH_RESOURCES_PATH`, `SSH_CERT_TTL_MINUTES`. Tasks 5 and 6 consume these.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_config.py`)

```python
def test_ssh_defaults():
    cfg = Config.from_env({})
    assert cfg.ssh_ca_path.endswith("ssh_ca.json")
    assert cfg.ssh_resources_path.endswith("ssh_resources.json")
    assert cfg.ssh_cert_ttl_minutes == 15


def test_ssh_cert_ttl_must_be_positive():
    import pytest
    from broker.config import ConfigError
    with pytest.raises(ConfigError):
        Config.from_env({"SSH_CERT_TTL_MINUTES": "0"})
    with pytest.raises(ConfigError):
        Config.from_env({"SSH_CERT_TTL_MINUTES": "soon"})


def test_ssh_paths_follow_agentgate_home():
    import os
    cfg = Config.from_env({"AGENTGATE_HOME": os.path.join("srv", "ag")})
    assert cfg.ssh_ca_path == os.path.join("srv", "ag", "ssh_ca.json")
    assert cfg.ssh_resources_path == os.path.join("srv", "ag", "ssh_resources.json")
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_config.py -k ssh -q`
Expected: FAIL (`AttributeError` / `TypeError`: unknown fields).

- [ ] **Step 3: Implement** (three edits to `broker/config.py`)

Add to `_DEFAULTS`:
```python
    "SSH_CERT_TTL_MINUTES": "15",
```

Add to the dict returned by `_default_paths`:
```python
        "SSH_CA_PATH": os.path.join(base, "ssh_ca.json"),
        "SSH_RESOURCES_PATH": os.path.join(base, "ssh_resources.json"),
```

Add dataclass fields (after `db_reap_interval_seconds`):
```python
    ssh_ca_path: str = os.path.join("data", "ssh_ca.json")
    ssh_resources_path: str = os.path.join("data", "ssh_resources.json")
    ssh_cert_ttl_minutes: int = 15
```

Add to the `cls(...)` call in `from_env` (after the db args):
```python
            ssh_ca_path=_require_non_empty(get("SSH_CA_PATH"), "SSH_CA_PATH"),
            ssh_resources_path=_require_non_empty(
                get("SSH_RESOURCES_PATH"), "SSH_RESOURCES_PATH"
            ),
            ssh_cert_ttl_minutes=_require_int(
                get("SSH_CERT_TTL_MINUTES"), "SSH_CERT_TTL_MINUTES", minimum=1
            ),
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_config.py -q`
Expected: PASS (all config tests).

- [ ] **Step 5: Commit**

```bash
git add broker/config.py tests/test_config.py
git commit -m "feat: config for SSH broker (CA path, resources path, cert TTL)"
```

---

### Task 5: Audit key_id + broker path + MCP tool + wiring

**Files:**
- Modify: `broker/audit.py`, `broker/mcp_server.py`, `broker/main.py`
- Test: `tests/test_audit.py` (append), `tests/test_ssh_tool.py` (create), `tests/test_main.py` (append)

**Interfaces:**
- Consumes: `SshResourceStore`/`SshResource` (Task 3), `SshCaStore` (Task 3), `ssh_ca.issue_certificate` (Task 2), `Config.ssh_*` (Task 4), existing `_authenticate`/`_flooded`/`_current_engine`/`ApprovalQueue`.
- Produces: `AuditLogger.log(..., key_id: str | None = None)`; `Broker.__init__(..., ssh_resources=None, ssh_ca=None)`; `Broker.request_ssh_certificate(agent, agent_key, resource) -> dict`; MCP tool `ssh_certificate_request`; `build_broker` wires both stores. Task 6/7 rely on the tool and wiring.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_audit.py`:

```python
def test_log_accepts_key_id(tmp_path):
    import json
    from broker.audit import AuditLogger
    path = tmp_path / "audit.log"
    AuditLogger(str(path)).log(
        agent="claude-code", credential_requested="web-1", policy_matched="p",
        decision="approved", mode="auto", token_expiry="2026-07-05T10:15:00+00:00",
        username="deploy", key_id="agentgate:claude-code:web-1",
    )
    entry = json.loads(path.read_text().strip())
    assert entry["key_id"] == "agentgate:claude-code:web-1"


def test_log_omits_key_id_when_absent(tmp_path):
    import json
    from broker.audit import AuditLogger
    path = tmp_path / "audit.log"
    AuditLogger(str(path)).log(
        agent="a", credential_requested="k", policy_matched="p",
        decision="denied", mode="auto", token_expiry=None,
    )
    assert "key_id" not in json.loads(path.read_text().strip())
```

Create `tests/test_ssh_tool.py`:

```python
# tests/test_ssh_tool.py
from __future__ import annotations

import json
import textwrap

import pytest

from broker.agent_store import AgentStore
from broker.approval import ApprovalQueue
from broker.audit import AuditLogger
from broker.config import Config
from broker.credential_store import CredentialStore
from broker.mcp_server import Broker, build_mcp
from broker.policy_engine import PolicyEngine
from broker.ssh_ca_store import SshCaStore
from broker.ssh_resource_store import SshResource, SshResourceStore

_NULL_FIELDS = ("host", "port", "username", "private_key", "certificate", "expires_at")


def _write_policies(tmp_path, body):
    p = tmp_path / "policies.yaml"
    p.write_text(textwrap.dedent(body))
    return str(p)


def _make_broker(tmp_path, *, policies, with_ssh=True, ca_initialized=True):
    cfg = Config.from_env({
        "POLICIES_PATH": _write_policies(tmp_path, policies),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTS_PATH": str(tmp_path / "agents.json"),
        "SSH_CA_PATH": str(tmp_path / "ssh_ca.json"),
        "SSH_RESOURCES_PATH": str(tmp_path / "ssh.json"),
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
    broker = Broker(
        config=cfg,
        store=CredentialStore(cfg.credentials_path, "pw"),
        engine=PolicyEngine.from_file(cfg.policies_path),
        audit=AuditLogger(cfg.logs_path),
        approvals=ApprovalQueue(),
        agents=agents,
        ssh_resources=ssh_resources,
        ssh_ca=ssh_ca,
    )
    return broker, agent_key, tmp_path / "audit.log"


_ALLOW = """
    policies:
      - name: cc-ssh
        agent: claude-code
        credential: web-1
        auto_approve: true
        escalate: false
"""

_DENY = """
    policies:
      - name: no-ssh
        agent: "*"
        credential: "*"
        auto_approve: false
        escalate: false
"""


def _assert_denied_shape(result):
    assert result["granted"] is False
    for f in _NULL_FIELDS:
        assert result[f] is None, f


async def test_grant_returns_key_cert_and_audits_without_private_key(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW)
    result = await broker.request_ssh_certificate("claude-code", key, "web-1")
    assert result["granted"] is True
    assert result["host"] == "10.0.0.5" and result["port"] == 22
    assert result["username"] == "deploy"
    assert result["private_key"].startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert result["certificate"].startswith("ssh-ed25519-cert-v01@openssh.com ")
    assert result["expires_at"]
    log_text = log.read_text()
    entry = json.loads(log_text.strip().splitlines()[-1])
    assert entry["decision"] == "approved"
    assert entry["username"] == "deploy"
    assert entry["key_id"] == "agentgate:claude-code:web-1"
    # The private key must NEVER appear anywhere in the audit file.
    assert "PRIVATE KEY" not in log_text
    body = result["private_key"].strip().splitlines()[1]  # a base64 line of the key
    assert body not in log_text


async def test_unknown_agent_denied_and_never_escalates(tmp_path):
    broker, _key, log = _make_broker(tmp_path, policies=_ALLOW)
    result = await broker.request_ssh_certificate("ghost", "bad-key", "web-1")
    _assert_denied_shape(result)
    assert broker.approvals.pending_count() == 0
    assert '"decision": "denied"' in log.read_text()


async def test_policy_hard_deny(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_DENY)
    result = await broker.request_ssh_certificate("claude-code", key, "web-1")
    _assert_denied_shape(result)
    assert "denied by policy" in result["reason"]
    assert '"decision": "denied"' in log.read_text()


async def test_unknown_resource_fails_closed(tmp_path):
    broker, key, log = _make_broker(
        tmp_path,
        policies="""
    policies:
      - name: cc-ssh
        agent: claude-code
        credential: "*"
        auto_approve: true
        escalate: false
""",
    )
    result = await broker.request_ssh_certificate("claude-code", key, "nope")
    _assert_denied_shape(result)
    assert "unknown ssh resource" in result["reason"]
    assert '"decision": "denied"' in log.read_text()


async def test_no_ssh_stores_configured_fails_closed(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW, with_ssh=False)
    result = await broker.request_ssh_certificate("claude-code", key, "web-1")
    _assert_denied_shape(result)
    assert '"decision": "denied"' in log.read_text()


async def test_uninitialized_ca_fails_closed(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW, ca_initialized=False)
    result = await broker.request_ssh_certificate("claude-code", key, "web-1")
    _assert_denied_shape(result)
    assert "ssh CA not initialized" in result["reason"]
    assert '"decision": "denied"' in log.read_text()


async def test_resource_store_failure_fails_closed_generic(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW)

    class _Boom:
        def get(self, name):
            raise RuntimeError("SENSITIVE_STORE_DETAIL")

    broker.ssh_resources = _Boom()
    result = await broker.request_ssh_certificate("claude-code", key, "web-1")
    _assert_denied_shape(result)
    assert "SENSITIVE_STORE_DETAIL" not in result["reason"]
    log_text = log.read_text()
    assert '"decision": "denied"' in log_text
    assert "SENSITIVE_STORE_DETAIL" not in log_text


async def test_signing_failure_fails_closed_generic(tmp_path, monkeypatch):
    from broker import mcp_server as m
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW)

    def boom(*a, **kw):
        raise RuntimeError("SENSITIVE_SIGNING_DETAIL")

    monkeypatch.setattr(m.ssh_ca, "issue_certificate", boom)
    result = await broker.request_ssh_certificate("claude-code", key, "web-1")
    _assert_denied_shape(result)
    assert "SENSITIVE_SIGNING_DETAIL" not in result["reason"]
    assert "could not issue certificate" in result["reason"]
    log_text = log.read_text()
    assert '"decision": "denied"' in log_text
    assert "SENSITIVE_SIGNING_DETAIL" not in log_text


async def test_tool_registered_with_underscore_name(tmp_path):
    from fastmcp import Client
    broker, key, _log = _make_broker(tmp_path, policies=_ALLOW)
    mcp = build_mcp(broker)
    async with Client(mcp) as client:
        names = [t.name for t in await client.list_tools()]
        assert "ssh_certificate_request" in names
        res = await client.call_tool("ssh_certificate_request", {
            "agent": "claude-code", "agent_key": key, "resource": "web-1"})
        assert res.data["granted"] is True
```

Append to `tests/test_main.py`:

```python
def test_build_broker_wires_ssh_stores(tmp_path):
    from broker import main as m
    cfg = Config.from_env({
        "POLICIES_PATH": str(tmp_path / "p.yaml"),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTS_PATH": str(tmp_path / "agents.json"),
        "DB_RESOURCES_PATH": str(tmp_path / "db.json"),
        "SSH_CA_PATH": str(tmp_path / "ssh_ca.json"),
        "SSH_RESOURCES_PATH": str(tmp_path / "ssh.json"),
    })
    (tmp_path / "p.yaml").write_text(
        'policies:\n  - name: d\n    agent: "*"\n    credential: "*"\n'
        "    auto_approve: false\n    escalate: true\n")
    broker = m.build_broker(cfg, "pw")
    assert broker.ssh_resources is not None
    assert broker.ssh_ca is not None
```

Note: these idioms are verified against `tests/test_db_tool.py` — `AgentStore.register(name)` returns the agent key; `ApprovalQueue.pending_count()` exists; tool listing uses `fastmcp.Client` inside an async test exactly as above.

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_ssh_tool.py tests/test_audit.py -q`
Expected: FAIL (`AttributeError`/`TypeError`: no `request_ssh_certificate`, unknown `key_id`/`ssh_resources` kwargs).

- [ ] **Step 3: Implement**

`broker/audit.py` — add parameter after `grants`:

```python
        key_id: str | None = None,
```

and after the `grants` inclusion:

```python
        if key_id is not None:
            entry["key_id"] = key_id
```

`broker/mcp_server.py`:

Imports (with the other `broker.` imports):
```python
from broker import ssh_ca
from broker.ssh_ca_store import SshCaStore
from broker.ssh_resource_store import SshResourceStore
```

`Broker.__init__` — add params after `db_executor`:
```python
        ssh_resources: SshResourceStore | None = None,
        ssh_ca: SshCaStore | None = None,
```
and assignments (note: the attribute is `ssh_ca_store` to avoid shadowing the `ssh_ca` module import):
```python
        self.ssh_resources = ssh_resources
        self.ssh_ca = ssh_ca
```

**Naming caution:** the module import `from broker import ssh_ca` and the constructor parameter `ssh_ca` coexist: inside `__init__` the parameter shadows the module (harmless — `__init__` doesn't call the module), and everywhere else use `self.ssh_ca` (the store) vs the module-level `ssh_ca.issue_certificate(...)`. The tests monkeypatch `m.ssh_ca.issue_certificate`, so `_grant_ssh` must call it as `ssh_ca.issue_certificate(...)` (module attribute), not via a `from`-imported bare function.

Add after `_escalate_db` (mirrors the db path exactly):

```python
    @staticmethod
    def _ssh_deny(reason: str) -> dict:
        return {
            "granted": False, "host": None, "port": None, "username": None,
            "private_key": None, "certificate": None, "expires_at": None,
            "reason": reason,
        }

    async def request_ssh_certificate(self, agent: str, agent_key: str, resource: str) -> dict:
        self.total_requests += 1
        mode = state.read_mode(self.config.state_path)

        if not self._authenticate(agent, agent_key, resource, mode):
            return self._ssh_deny("unknown agent or invalid agent key")

        if mode == "manual":
            return await self._escalate_ssh(agent, resource, mode, "manual-mode")

        decision = self._current_engine().evaluate(agent, resource)
        if decision.auto_approve:
            return await self._grant_ssh(agent, resource, mode, decision.policy_name)
        if not decision.escalate:
            self.audit.log(
                agent=agent, credential_requested=resource,
                policy_matched=decision.policy_name, decision="denied",
                mode=mode, token_expiry=None,
            )
            return self._ssh_deny(f"denied by policy '{decision.policy_name}'")
        return await self._escalate_ssh(agent, resource, mode, decision.policy_name)

    async def _grant_ssh(self, agent: str, resource: str, mode: str, policy_name: str) -> dict:
        if self.ssh_resources is None:
            res = None
        else:
            try:
                res = self.ssh_resources.get(resource)
            except KeyError:
                res = None
            except Exception:
                # A store failure must fail closed WITH an audit row and the
                # standard deny shape; reason stays generic (no internals leak).
                self.audit.log(
                    agent=agent, credential_requested=resource, policy_matched=policy_name,
                    decision="denied", mode=mode, token_expiry=None,
                )
                return self._ssh_deny(f"could not access ssh resource '{resource}'")
        if res is None or self.ssh_ca is None:
            self.audit.log(
                agent=agent, credential_requested=resource, policy_matched=policy_name,
                decision="denied", mode=mode, token_expiry=None,
            )
            return self._ssh_deny(f"unknown ssh resource '{resource}'")

        try:
            ca_pem = self.ssh_ca.load_private_pem()
        except KeyError:
            self.audit.log(
                agent=agent, credential_requested=resource, policy_matched=policy_name,
                decision="denied", mode=mode, token_expiry=None,
            )
            return self._ssh_deny("ssh CA not initialized")
        except Exception:
            self.audit.log(
                agent=agent, credential_requested=resource, policy_matched=policy_name,
                decision="denied", mode=mode, token_expiry=None,
            )
            return self._ssh_deny("could not access ssh CA")

        key_id = f"agentgate:{agent}:{resource}"
        try:
            cred = ssh_ca.issue_certificate(
                ca_pem, key_id=key_id, principal=res.principal,
                ttl_minutes=self.config.ssh_cert_ttl_minutes,
                force_command=res.force_command,
            )
        except Exception:
            # Fail closed: never leak crypto/validation internals; always audit.
            self.audit.log(
                agent=agent, credential_requested=resource, policy_matched=policy_name,
                decision="denied", mode=mode, token_expiry=None,
            )
            return self._ssh_deny(f"could not issue certificate for '{resource}'")

        self.audit.log(
            agent=agent, credential_requested=resource, policy_matched=policy_name,
            decision="approved", mode=mode, token_expiry=cred.expires_at,
            username=res.principal, key_id=key_id,
        )
        return {
            "granted": True, "host": res.host, "port": res.port,
            "username": res.principal, "private_key": cred.private_key,
            "certificate": cred.certificate, "expires_at": cred.expires_at,
            "reason": f"auto-approved by policy '{policy_name}'",
        }

    async def _escalate_ssh(self, agent: str, resource: str, mode: str, policy_name: str) -> dict:
        if self._flooded(agent, resource, mode, policy_name):
            return self._ssh_deny("too many requests pending operator approval")
        self.escalated_requests += 1
        self.audit.log(
            agent=agent, credential_requested=resource, policy_matched=policy_name,
            decision="escalated", mode=mode, token_expiry=None,
        )
        try:
            approved = await self.approvals.submit(
                agent, resource, timeout=self.config.escalation_timeout_seconds or None
            )
        except asyncio.TimeoutError:
            self.audit.log(
                agent=agent, credential_requested=resource, policy_matched=policy_name,
                decision="expired", mode=mode, token_expiry=None,
            )
            return self._ssh_deny("escalation timed out")
        if approved:
            return await self._grant_ssh(agent, resource, mode, f"manual:{policy_name}")
        self.audit.log(
            agent=agent, credential_requested=resource, policy_matched=policy_name,
            decision="denied", mode=mode, token_expiry=None,
        )
        return self._ssh_deny("denied by operator")
```

In `build_mcp`, after the `db_credential_request` tool:

```python
    @mcp.tool(name="ssh_certificate_request")
    async def ssh_certificate_request(agent: str, agent_key: str, resource: str) -> dict:
        return await broker.request_ssh_certificate(agent, agent_key, resource)
```

`broker/main.py` — imports:
```python
from broker.ssh_ca_store import SshCaStore
from broker.ssh_resource_store import SshResourceStore
```
and in `build_broker`'s `Broker(...)` call, after `db_executor=...`:
```python
        ssh_resources=SshResourceStore(config.ssh_resources_path, master_password),
        ssh_ca=SshCaStore(config.ssh_ca_path, master_password),
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_ssh_tool.py tests/test_audit.py tests/test_main.py -q`
Expected: PASS. Then run the full suite: `python -m pytest -q` — expected all pass, no regressions (integration tests skipped).

- [ ] **Step 5: Commit**

```bash
git add broker/audit.py broker/mcp_server.py broker/main.py tests/test_ssh_tool.py tests/test_audit.py tests/test_main.py
git commit -m "feat: ssh_certificate_request broker path + MCP tool; audit key_id"
```

---

### Task 6: CLI `ssh-ca-init` / `ssh-ca-pub` / `ssh-add` / `ssh-list` / `ssh-remove`

**Files:**
- Modify: `cli/commands.py`
- Test: `tests/test_ssh_cli.py`

**Interfaces:**
- Consumes: `SshCaStore`/`SshCaExistsError`, `SshResource`/`SshResourceStore` (Task 3), `validate_principal`/`validate_force_command`/`SshValidationError` (Task 1), existing `_password`, `build_parser`, `run`, `AuditLogger`.
- Produces: five subcommands. `ssh-ca-init` audited as `log_operator(action="ssh-ca-init", subject="ssh-ca")`; `ssh-add`/`ssh-remove` audited with the resource name as subject. Invalid principal/force-command → exit 2, nothing stored. Existing CA → exit 1, untouched.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_ssh_cli.py
from __future__ import annotations

import textwrap

from broker.config import Config
from broker.ssh_ca_store import SshCaStore
from broker.ssh_resource_store import SshResourceStore
from cli import commands


def _cfg(tmp_path):
    (tmp_path / "p.yaml").write_text(textwrap.dedent("""
        policies:
          - name: d
            agent: "*"
            credential: "*"
            auto_approve: false
            escalate: true
    """))
    return Config.from_env({
        "POLICIES_PATH": str(tmp_path / "p.yaml"),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTS_PATH": str(tmp_path / "agents.json"),
        "SSH_CA_PATH": str(tmp_path / "ssh_ca.json"),
        "SSH_RESOURCES_PATH": str(tmp_path / "ssh.json"),
    })


def test_ssh_ca_init_and_pub(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    assert commands.run(["ssh-ca-init"], config=cfg, master_password="pw") == 0
    out = capsys.readouterr().out
    assert "ssh-ed25519 " in out
    assert "TrustedUserCAKeys" in out  # setup instructions printed
    assert "PRIVATE KEY" not in out

    assert commands.run(["ssh-ca-pub"], config=cfg, master_password="pw") == 0
    out = capsys.readouterr().out
    assert out.strip().startswith("ssh-ed25519 ")

    log = (tmp_path / "audit.log").read_text()
    assert '"action": "ssh-ca-init"' in log
    assert "PRIVATE KEY" not in log


def test_ssh_ca_init_twice_refuses(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    assert commands.run(["ssh-ca-init"], config=cfg, master_password="pw") == 0
    capsys.readouterr()
    pem_before = SshCaStore(cfg.ssh_ca_path, "pw").load_private_pem()
    assert commands.run(["ssh-ca-init"], config=cfg, master_password="pw") == 1
    # Existing CA untouched.
    assert SshCaStore(cfg.ssh_ca_path, "pw").load_private_pem() == pem_before


def test_ssh_ca_pub_before_init_fails(tmp_path):
    cfg = _cfg(tmp_path)
    assert commands.run(["ssh-ca-pub"], config=cfg, master_password="pw") == 1


def test_ssh_add_list_remove(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    rc = commands.run([
        "ssh-add", "web-1", "--host", "10.0.0.5", "--port", "22",
        "--principal", "deploy", "--force-command", "systemctl restart myapp",
    ], config=cfg, master_password="pw")
    assert rc == 0

    res = SshResourceStore(cfg.ssh_resources_path, "pw").get("web-1")
    assert res.principal == "deploy"
    assert res.force_command == "systemctl restart myapp"

    assert commands.run(["ssh-list"], config=cfg, master_password="pw") == 0
    out = capsys.readouterr().out
    assert "web-1" in out and "deploy" in out

    assert commands.run(["ssh-remove", "web-1"], config=cfg, master_password="pw") == 0
    assert SshResourceStore(cfg.ssh_resources_path, "pw").list_names() == []

    log = (tmp_path / "audit.log").read_text()
    assert '"action": "ssh-add"' in log and '"action": "ssh-remove"' in log


def test_ssh_add_without_force_command(tmp_path):
    cfg = _cfg(tmp_path)
    rc = commands.run([
        "ssh-add", "web-2", "--host", "h", "--port", "22", "--principal", "deploy",
    ], config=cfg, master_password="pw")
    assert rc == 0
    assert SshResourceStore(cfg.ssh_resources_path, "pw").get("web-2").force_command is None


def test_ssh_add_rejects_bad_principal(tmp_path):
    cfg = _cfg(tmp_path)
    rc = commands.run([
        "ssh-add", "bad", "--host", "h", "--port", "22", "--principal", "Root",
    ], config=cfg, master_password="pw")
    assert rc == 2
    assert SshResourceStore(cfg.ssh_resources_path, "pw").list_names() == []
    # No audit row for a rejected add.
    assert '"action": "ssh-add"' not in (tmp_path / "audit.log").read_text()


def test_ssh_remove_unknown_fails(tmp_path):
    cfg = _cfg(tmp_path)
    assert commands.run(["ssh-remove", "nope"], config=cfg, master_password="pw") == 1
    assert '"action": "ssh-remove"' not in (tmp_path / "audit.log").read_text()
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_ssh_cli.py -q`
Expected: FAIL (`SystemExit: 2` from argparse — unknown subcommand `ssh-ca-init`).

- [ ] **Step 3: Implement**

In `cli/commands.py`, add imports:

```python
from broker.ssh_ca_store import SshCaExistsError, SshCaStore
from broker.ssh_resource_store import SshResource, SshResourceStore
from broker.ssh_validation import SshValidationError, validate_force_command, validate_principal
```

In `build_parser`, after the `db-remove` subparser:

```python
    sub.add_parser("ssh-ca-init", help="create the SSH certificate authority")
    sub.add_parser("ssh-ca-pub", help="print the CA public key line for sshd_config")
    sa = sub.add_parser("ssh-add", help="register an SSH server resource")
    sa.add_argument("name")
    sa.add_argument("--host", required=True)
    sa.add_argument("--port", type=int, required=True)
    sa.add_argument("--principal", required=True, help="login user certificates are pinned to")
    sa.add_argument("--force-command", default=None, dest="force_command",
                    help="restrict certificates to this single command")
    sub.add_parser("ssh-list", help="list registered SSH resources")
    sr = sub.add_parser("ssh-remove", help="remove an SSH resource")
    sr.add_argument("name")
```

In `run`, before the final `return 2`:

```python
    if args.command == "ssh-ca-init":
        store = SshCaStore(config.ssh_ca_path, _password(master_password))
        try:
            pub = store.initialize()
        except SshCaExistsError:
            print("ssh CA already initialized (refusing to overwrite: every "
                  "enrolled server trusts the existing key)", file=sys.stderr)
            return 1
        AuditLogger(config.logs_path).log_operator(action="ssh-ca-init", subject="ssh-ca")
        print("SSH CA created. Enroll each server by installing this public key,")
        print("then add to /etc/ssh/sshd_config:  TrustedUserCAKeys /etc/ssh/agentgate_ca.pub")
        print(pub)
        return 0

    if args.command == "ssh-ca-pub":
        store = SshCaStore(config.ssh_ca_path, _password(master_password))
        try:
            print(store.public_line())
        except KeyError:
            print("ssh CA not initialized (run ssh-ca-init first)", file=sys.stderr)
            return 1
        return 0

    if args.command == "ssh-add":
        try:
            principal = validate_principal(args.principal)
            force_command = (
                validate_force_command(args.force_command)
                if args.force_command is not None else None
            )
        except SshValidationError as exc:
            print(f"invalid ssh resource: {exc}", file=sys.stderr)
            return 2
        SshResourceStore(config.ssh_resources_path, _password(master_password)).store(
            SshResource(
                name=args.name, host=args.host, port=args.port, principal=principal,
                force_command=force_command,
                created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(
                    timespec="seconds"
                ),
            )
        )
        AuditLogger(config.logs_path).log_operator(action="ssh-add", subject=args.name)
        print(f"registered ssh resource '{args.name}'")
        return 0

    if args.command == "ssh-list":
        store = SshResourceStore(config.ssh_resources_path, _password(master_password))
        for meta in store.list_metadata():
            forced = f"  [force-command: {meta['force_command']}]" if meta["force_command"] else ""
            print(f"{meta['name']}  {meta['principal']}@{meta['host']}:{meta['port']}{forced}")
        return 0

    if args.command == "ssh-remove":
        store = SshResourceStore(config.ssh_resources_path, _password(master_password))
        try:
            store.delete(args.name)
        except KeyError:
            print(f"no such ssh resource '{args.name}'", file=sys.stderr)
            return 1
        AuditLogger(config.logs_path).log_operator(action="ssh-remove", subject=args.name)
        print(f"removed ssh resource '{args.name}'")
        return 0
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_ssh_cli.py -q`
Expected: PASS. Then `python -m pytest -q` — all pass, no regressions.

- [ ] **Step 5: Commit**

```bash
git add cli/commands.py tests/test_ssh_cli.py
git commit -m "feat: CLI ssh-ca-init/ssh-ca-pub/ssh-add/ssh-list/ssh-remove with operator audit"
```

---

### Task 7: Docs + skip-gated integration test

**Files:**
- Modify: `.env.example`, `README.md`
- Create: `tests/test_ssh_integration.py`

**Interfaces:**
- Consumes: everything above.
- Produces: docs for the SSH broker; a skip-gated real-sshd end-to-end test. No new dependencies (the `ssh` client binary is invoked via subprocess only inside the skip-gated test).

- [ ] **Step 1: Write the integration test (skip-gated)**

```python
# tests/test_ssh_integration.py
from __future__ import annotations

import os
import subprocess
import time

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("AGENTGATE_TEST_SSH_HOST"),
    reason=(
        "set AGENTGATE_TEST_SSH_HOST (and optionally AGENTGATE_TEST_SSH_PORT, "
        "AGENTGATE_TEST_SSH_PRINCIPAL, AGENTGATE_TEST_SSH_CA_PEM) to run against a real "
        "sshd whose sshd_config trusts the CA via TrustedUserCAKeys"
    ),
)


def _target():
    return dict(
        host=os.environ["AGENTGATE_TEST_SSH_HOST"],
        port=int(os.environ.get("AGENTGATE_TEST_SSH_PORT", "22")),
        principal=os.environ.get("AGENTGATE_TEST_SSH_PRINCIPAL", "agentgate-itest"),
    )


def _ca_pem(tmp_path):
    # Use the operator-provided CA (the one the server already trusts) when
    # given; otherwise generate one — which only works if the server trusts it.
    path = os.environ.get("AGENTGATE_TEST_SSH_CA_PEM")
    if path:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    from broker.ssh_ca import generate_ca
    return generate_ca().private_key_pem


def _ssh(tmp_path, private_key, certificate, target, command):
    key = tmp_path / "id_agentgate"
    key.write_text(private_key)
    key.chmod(0o600)
    (tmp_path / "id_agentgate-cert.pub").write_text(certificate)
    return subprocess.run(
        [
            "ssh", "-i", str(key),
            "-o", f"CertificateFile={tmp_path / 'id_agentgate-cert.pub'}",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes",
            "-p", str(target["port"]),
            f"{target['principal']}@{target['host']}",
            command,
        ],
        capture_output=True, text=True, timeout=30,
    )


def test_cert_login_expiry_and_force_command(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization.ssh import (
        SSHCertificateBuilder, SSHCertificateType,
    )

    from broker.ssh_ca import generate_keypair, issue_certificate

    target = _target()
    ca_pem = _ca_pem(tmp_path)

    # 1. A freshly issued cert logs in as the pinned principal.
    cred = issue_certificate(
        ca_pem, key_id="agentgate:itest:login", principal=target["principal"], ttl_minutes=5,
    )
    result = _ssh(tmp_path, cred.private_key, cred.certificate, target, "echo login-ok")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "login-ok"

    # 2. An expired cert is refused (built test-locally with a past window).
    ca_key = serialization.load_ssh_private_key(ca_pem.encode(), password=None)
    pair = generate_keypair()
    user_pub = serialization.load_ssh_public_key(pair.public_key_openssh.encode())
    now = int(time.time())
    expired = (
        SSHCertificateBuilder()
        .public_key(user_pub).serial(1).type(SSHCertificateType.USER)
        .key_id(b"agentgate:itest:expired")
        .valid_principals([target["principal"].encode()])
        .valid_after(now - 7200).valid_before(now - 3600)
        .add_extension(b"permit-pty", b"")
        .sign(ca_key)
    )
    result = _ssh(
        tmp_path, pair.private_key_pem, expired.public_bytes().decode(), target, "echo bad",
    )
    assert result.returncode != 0  # sshd refuses the expired certificate

    # 3. force-command overrides whatever the client asks to run.
    forced = issue_certificate(
        ca_pem, key_id="agentgate:itest:forced", principal=target["principal"],
        ttl_minutes=5, force_command="echo forced-ok",
    )
    result = _ssh(tmp_path, forced.private_key, forced.certificate, target, "echo something-else")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "forced-ok"
```

- [ ] **Step 2: Run to verify it skips cleanly**

Run: `python -m pytest tests/test_ssh_integration.py -q`
Expected: `1 skipped` (no `AGENTGATE_TEST_SSH_HOST` set).

- [ ] **Step 3: Docs**

`.env.example` — add after the DB broker block:

```
# SSH broker: encrypted CA + resource store paths and certificate TTL.
# One-time: `agentgate ssh-ca-init`, install the printed key on each server
# (TrustedUserCAKeys), then register servers with `agentgate ssh-add`.
# SSH_CA_PATH=./data/ssh_ca.json
# SSH_RESOURCES_PATH=./data/ssh_resources.json
SSH_CERT_TTL_MINUTES=15
```

`README.md`:
1. In the `## MCP Tools` intro: change "7 MCP tools" → "8 MCP tools" and "The four that grant or change anything" → "The five that grant or change anything".
2. Add a numbered entry for **`ssh_certificate_request(agent, agent_key, resource)`** — returns `{granted, host, port, username, private_key, certificate, expires_at, reason}`; when denied all credential fields are `null`. Note that the granted `private_key` **is** a working (TTL-limited) SSH key — treat the response as secret.
3. Add a `## SSH Broker` section after the PostgreSQL Infra Broker section covering: the model (AgentGate is an SSH CA; certificates are short-lived, principal-pinned, `permit-pty` only with all forwarding disabled; sshd enforces expiry natively — no reaper); one-time setup (`agentgate ssh-ca-init`, install the public key as `/etc/ssh/agentgate_ca.pub`, add `TrustedUserCAKeys /etc/ssh/agentgate_ca.pub` to `sshd_config`, reload sshd); registering servers (`agentgate ssh-add web-1 --host 10.0.0.5 --port 22 --principal deploy --force-command "systemctl restart myapp"`); agent usage (`ssh -i agent_key -o CertificateFile=agent_key-cert.pub deploy@host`; the `key_id agentgate:<agent>:<resource>` appears in the server's sshd logs so every login traces to an agent); and a residual-risk note: AgentGate holds a CA key every enrolled server trusts — compromise means access to all enrolled servers as any registered principal until `TrustedUserCAKeys` is removed; there is no pre-expiry revocation (no KRL) — the TTL is the control.
4. Add the three new env vars (`SSH_CA_PATH`, `SSH_RESOURCES_PATH`, `SSH_CERT_TTL_MINUTES`) to the `## ECS Migration` section, matching the existing style.

- [ ] **Step 4: Run the full suite**

Run: `python -m pytest -q`
Expected: PASS (all prior tests plus the new ones; both integration tests skipped).

- [ ] **Step 5: Commit**

```bash
git add .env.example README.md tests/test_ssh_integration.py
git commit -m "feat: SSH broker docs + skip-gated real-sshd integration test"
```

---

## Self-Review

**Spec coverage:**
- CA model, `TrustedUserCAKeys`, no per-server credential → Tasks 2, 3, 7 (docs). ✓
- Broker-generated Ed25519 keypair per grant, private key + cert in response → Tasks 2, 5. ✓
- Principal pinning + optional force-command; forwarding/X11/user-rc disabled, `permit-pty` only → Task 2 (fixed extension set, tested exactly). ✓
- Validate at input AND sink, canonical patterns in a leaf module → Task 1 (`ssh_validation.py`), Task 2 (sink re-validation), Task 6 (input validation at `ssh-add`). ✓
- sshd-native expiry, no reaper → no reaper task anywhere; `valid_before` tested in Task 2. ✓
- CA encrypted at rest; initialize-twice refuses; load-absent raises → Task 3. ✓
- `SshResource` store (no secrets; EncryptedStore base for perms/atomicity only) → Task 3. ✓
- Config (`SSH_CA_PATH`, `SSH_RESOURCES_PATH`, `SSH_CERT_TTL_MINUTES` ≥1 default 15) → Task 4. ✓
- Broker path mirrors db path; all fail-closed paths from the spec's error table (uninitialized CA, decrypt/store failure generic, unknown resource, signing failure generic, auth-before-escalation, flood, timeout, operator deny) → Task 5 (each has a test). ✓
- Audit `key_id`/username, never key material → Task 5 (audit param + explicit not-in-log tests). ✓
- Tool `ssh_certificate_request`, 8 tools / 5 grant-or-change → Tasks 5, 7. ✓
- CLI five subcommands + operator audit + exit codes from the spec's error table → Task 6. ✓
- Skip-gated integration test (login works, expired refused, force-command enforced) → Task 7. ✓
- Out-of-scope items (KRL, host certs, agent-submitted pubkeys, source-address pinning) → correctly absent. ✓

**Placeholder scan:** none — every code step carries complete code; the only prose step is Task 7's README content, which enumerates exact required text and numbers.

**Type consistency:** `IssuedCredential(private_key, certificate, expires_at)` (Task 2) matches `_grant_ssh`'s `cred.private_key/certificate/expires_at` (Task 5). `SshResource(name, host, port, principal, force_command, created_at)` consistent across Tasks 3, 5, 6. `SshCaStore.initialize()/load_private_pem()/public_line()/is_initialized()` consistent across Tasks 3, 5, 6. `validate_principal/validate_force_command/validate_key_id` consistent across Tasks 1, 2, 6. Deny shape keys identical between `_ssh_deny` (Task 5) and the tests' `_NULL_FIELDS`.

**Notes for implementers:** pytest runs with `asyncio_mode = auto` — async test functions need no decorator. `AuditLogger.log_operator` already exists. Mirror `tests/test_db_tool.py`'s idioms for agent registration, `pending_count`, and tool-listing where this plan says to.
