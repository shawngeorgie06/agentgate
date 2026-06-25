# AgentGate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build AgentGate — an open-source credential broker that brokers API keys to AI agents over MCP, governed by YAML policies, with two-tier (auto/manual) approval, runtime mode toggle, and full audit logging.

**Architecture:** A `fastmcp` server exposes credential/policy tools to agents. Each `credential.request` reads the current mode from a mounted state file, evaluates the request against a first-match YAML policy engine, and either issues a scoped time-limited token (auto) or escalates to an interactive async CLI for `[y/n]` approval (manual / no-match). Credentials are stored AES-256-GCM-encrypted with an Argon2id-derived key. Every decision is appended to a mounted JSONL audit log. All volume paths come from env.

**Tech Stack:** Python 3.11+, `fastmcp`, `cryptography` (AES-256-GCM), `argon2-cffi` (Argon2id), `PyYAML`, `pytest`, Docker Compose.

## Global Constraints

- Python 3.11+; no hardcoded filesystem paths anywhere — every path comes from env (`POLICIES_PATH`, `STATE_PATH`, `LOGS_PATH`, `CREDENTIALS_PATH`).
- Credentials (plaintext values) and issued tokens are NEVER written to logs, audit entries, or error messages. Errors reference credential *names* only.
- Mode is read from `state/mode.json` on every request — never cached in memory.
- Policy-mutating operations (`policy.add`) ALWAYS require human confirmation — hard-coded, not overridable by mode or any policy.
- Encryption: AES-256-GCM, per-credential random 96-bit nonce. Key: Argon2id (`argon2.low_level.hash_secret_raw`, 32-byte output) over a persisted random 16-byte salt.
- Master password: `AGENTGATE_MASTER_PASSWORD` env var, else interactive `getpass` prompt.
- Token TTL: `TOKEN_TTL_MINUTES` env (default 60).
- Mounted volumes (`policies/`, `state/`, `logs/`, `data/`) are reached only through env-configured paths.
- **Version control is performed by the operator, not the agent.** Each task ends at a "stage and pause" checkpoint: `git add` the files and stop. Do NOT run `git commit` or `git push`.
- Timestamps are ISO-8601, timezone-naive local time (`datetime.now().isoformat(timespec="seconds")`).

---

## File Structure

| File | Responsibility |
|------|----------------|
| `requirements.txt` | Pinned dependencies |
| `broker/config.py` | Central env → path/config resolver (no hardcoded paths) |
| `broker/credential_store.py` | Encrypted at-rest credential storage (store/retrieve/delete) |
| `broker/policy_engine.py` | Load/validate YAML, first-match evaluation incl. time windows |
| `broker/state.py` | Atomic read/write of `mode.json` |
| `broker/audit.py` | Append-only JSONL audit logging |
| `broker/approval.py` | Token issuance + escalation queue + manual approval resolution |
| `broker/mcp_server.py` | `fastmcp` tool definitions wiring the above together |
| `broker/main.py` | Async CLI: status line, `s` toggle, inline `[y/n]`, runs MCP server |
| `cli/commands.py` | Standalone operator commands (store/delete cred, validate, status) |
| `tests/*` | One test module per component |
| `.env.example`, `docker-compose.yml`, `Dockerfile`, `README.md` | Packaging |

Build order follows the spec: config → credential_store → policy_engine → state → audit → approval → mcp_server → main → cli → packaging.

---

## Task 0: Project scaffolding & config

**Files:**
- Create: `requirements.txt`, `broker/__init__.py`, `cli/__init__.py`, `tests/__init__.py`, `.gitignore`, `.env.example`
- Create: `broker/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Produces: `broker.config.Config` dataclass with fields `policies_path: str`, `state_path: str`, `logs_path: str`, `credentials_path: str`, `token_ttl_minutes: int`, `master_password: str | None`. Classmethod `Config.from_env(env: Mapping[str, str] | None = None) -> Config`.

- [ ] **Step 1: Write `requirements.txt`**

```
fastmcp>=2.0
cryptography>=42.0
argon2-cffi>=23.1
PyYAML>=6.0
pytest>=8.0
```

- [ ] **Step 2: Write `.gitignore`**

```
__pycache__/
*.pyc
.env
data/credentials.json
state/mode.json
logs/audit.log
.pytest_cache/
```

- [ ] **Step 3: Create empty package markers**

Create `broker/__init__.py`, `cli/__init__.py`, `tests/__init__.py` as empty files.

- [ ] **Step 4: Write the failing test** — `tests/test_config.py`

```python
from broker.config import Config


def test_from_env_uses_defaults_when_unset():
    cfg = Config.from_env({})
    assert cfg.policies_path.endswith("policies.yaml")
    assert cfg.state_path.endswith("mode.json")
    assert cfg.logs_path.endswith("audit.log")
    assert cfg.credentials_path.endswith("credentials.json")
    assert cfg.token_ttl_minutes == 60
    assert cfg.master_password is None


def test_from_env_reads_overrides():
    env = {
        "POLICIES_PATH": "/mnt/p.yaml",
        "STATE_PATH": "/mnt/s.json",
        "LOGS_PATH": "/mnt/a.log",
        "CREDENTIALS_PATH": "/mnt/c.json",
        "TOKEN_TTL_MINUTES": "15",
        "AGENTGATE_MASTER_PASSWORD": "hunter2",
    }
    cfg = Config.from_env(env)
    assert cfg.policies_path == "/mnt/p.yaml"
    assert cfg.state_path == "/mnt/s.json"
    assert cfg.logs_path == "/mnt/a.log"
    assert cfg.credentials_path == "/mnt/c.json"
    assert cfg.token_ttl_minutes == 15
    assert cfg.master_password == "hunter2"
```

- [ ] **Step 5: Run test to verify it fails**

Run: `pytest tests/test_config.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'broker.config'`

- [ ] **Step 6: Write `broker/config.py`**

```python
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping, Optional

_DEFAULTS = {
    "POLICIES_PATH": os.path.join("policies", "policies.yaml"),
    "STATE_PATH": os.path.join("state", "mode.json"),
    "LOGS_PATH": os.path.join("logs", "audit.log"),
    "CREDENTIALS_PATH": os.path.join("data", "credentials.json"),
    "TOKEN_TTL_MINUTES": "60",
}


@dataclass(frozen=True)
class Config:
    policies_path: str
    state_path: str
    logs_path: str
    credentials_path: str
    token_ttl_minutes: int
    master_password: Optional[str]

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Config":
        env = os.environ if env is None else env

        def get(key: str) -> str:
            return env.get(key, _DEFAULTS[key])

        return cls(
            policies_path=get("POLICIES_PATH"),
            state_path=get("STATE_PATH"),
            logs_path=get("LOGS_PATH"),
            credentials_path=get("CREDENTIALS_PATH"),
            token_ttl_minutes=int(get("TOKEN_TTL_MINUTES")),
            master_password=env.get("AGENTGATE_MASTER_PASSWORD"),
        )
```

- [ ] **Step 7: Write `.env.example`**

```
# Mounted volume paths (override for ECS task definitions)
POLICIES_PATH=./policies/policies.yaml
STATE_PATH=./state/mode.json
LOGS_PATH=./logs/audit.log
CREDENTIALS_PATH=./data/credentials.json

# Token lifetime in minutes
TOKEN_TTL_MINUTES=60

# Master password for credential encryption.
# If unset, the broker prompts interactively at startup.
AGENTGATE_MASTER_PASSWORD=
```

- [ ] **Step 8: Run test to verify it passes**

Run: `pytest tests/test_config.py -v`
Expected: PASS (2 passed)

- [ ] **Step 9: Stage and pause**

Run: `git add requirements.txt .gitignore .env.example broker/__init__.py cli/__init__.py tests/__init__.py broker/config.py tests/test_config.py`
Then stop for operator to commit.

---

## Task 1: credential_store.py — encrypted storage

**Files:**
- Create: `broker/credential_store.py`
- Test: `tests/test_credential_store.py`

**Interfaces:**
- Consumes: nothing (takes explicit `path` and `master_password` args).
- Produces: `class CredentialStore`:
  - `__init__(self, path: str, master_password: str)`
  - `store(self, name: str, value: str) -> None`
  - `retrieve(self, name: str) -> str` (raises `KeyError(name)` if absent)
  - `delete(self, name: str) -> None` (raises `KeyError(name)` if absent)
  - `list_names(self) -> list[str]`
  - Raises `CredentialDecryptionError` (subclass of `Exception`) on wrong password / tampered data.

- [ ] **Step 1: Write the failing test** — `tests/test_credential_store.py`

```python
import json
import pytest
from broker.credential_store import CredentialStore, CredentialDecryptionError


def test_store_and_retrieve_round_trip(tmp_path):
    path = tmp_path / "creds.json"
    store = CredentialStore(str(path), "master-pw")
    store.store("anthropic-api-key", "sk-ant-secret")
    assert store.retrieve("anthropic-api-key") == "sk-ant-secret"


def test_retrieve_missing_raises_keyerror(tmp_path):
    store = CredentialStore(str(tmp_path / "creds.json"), "pw")
    with pytest.raises(KeyError):
        store.retrieve("nope")


def test_delete_removes_credential(tmp_path):
    store = CredentialStore(str(tmp_path / "creds.json"), "pw")
    store.store("k", "v")
    store.delete("k")
    assert store.list_names() == []
    with pytest.raises(KeyError):
        store.delete("k")


def test_plaintext_never_on_disk(tmp_path):
    path = tmp_path / "creds.json"
    store = CredentialStore(str(path), "pw")
    store.store("k", "super-secret-value")
    raw = path.read_text()
    assert "super-secret-value" not in raw
    data = json.loads(raw)
    assert "salt" in data
    assert "nonce" in data["credentials"]["k"]
    assert "ciphertext" in data["credentials"]["k"]


def test_wrong_password_fails_to_decrypt(tmp_path):
    path = tmp_path / "creds.json"
    CredentialStore(str(path), "right-pw").store("k", "v")
    reopened = CredentialStore(str(path), "wrong-pw")
    with pytest.raises(CredentialDecryptionError):
        reopened.retrieve("k")


def test_salt_persists_across_instances(tmp_path):
    path = tmp_path / "creds.json"
    CredentialStore(str(path), "pw").store("k", "v")
    # New instance, same password, must decrypt existing data.
    assert CredentialStore(str(path), "pw").retrieve("k") == "v"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_credential_store.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'broker.credential_store'`

- [ ] **Step 3: Write `broker/credential_store.py`**

```python
from __future__ import annotations

import base64
import json
import os
from typing import Dict

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Argon2id parameters (interactive-grade; tune up for production hardware).
_ARGON2_TIME_COST = 3
_ARGON2_MEMORY_COST = 64 * 1024  # KiB
_ARGON2_PARALLELISM = 4
_KEY_LEN = 32  # AES-256
_SALT_LEN = 16
_NONCE_LEN = 12  # 96-bit GCM nonce


class CredentialDecryptionError(Exception):
    """Raised when a credential cannot be decrypted (wrong key or tampering)."""


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


class CredentialStore:
    def __init__(self, path: str, master_password: str) -> None:
        self._path = path
        self._password = master_password.encode("utf-8")
        self._data = self._load()
        self._key = self._derive_key(_b64d(self._data["salt"]))

    # --- persistence -----------------------------------------------------
    def _load(self) -> Dict:
        if os.path.exists(self._path):
            with open(self._path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        data = {"salt": _b64e(os.urandom(_SALT_LEN)), "credentials": {}}
        self._write(data)
        return data

    def _write(self, data: Dict) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self._path)), exist_ok=True)
        tmp = f"{self._path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, self._path)

    def _derive_key(self, salt: bytes) -> bytes:
        return hash_secret_raw(
            secret=self._password,
            salt=salt,
            time_cost=_ARGON2_TIME_COST,
            memory_cost=_ARGON2_MEMORY_COST,
            parallelism=_ARGON2_PARALLELISM,
            hash_len=_KEY_LEN,
            type=Type.ID,
        )

    # --- public API ------------------------------------------------------
    def store(self, name: str, value: str) -> None:
        nonce = os.urandom(_NONCE_LEN)
        ciphertext = AESGCM(self._key).encrypt(nonce, value.encode("utf-8"), None)
        self._data["credentials"][name] = {
            "nonce": _b64e(nonce),
            "ciphertext": _b64e(ciphertext),
        }
        self._write(self._data)

    def retrieve(self, name: str) -> str:
        if name not in self._data["credentials"]:
            raise KeyError(name)
        entry = self._data["credentials"][name]
        try:
            plaintext = AESGCM(self._key).decrypt(
                _b64d(entry["nonce"]), _b64d(entry["ciphertext"]), None
            )
        except InvalidTag as exc:
            raise CredentialDecryptionError(
                f"could not decrypt credential '{name}' (wrong password or tampered store)"
            ) from exc
        return plaintext.decode("utf-8")

    def delete(self, name: str) -> None:
        if name not in self._data["credentials"]:
            raise KeyError(name)
        del self._data["credentials"][name]
        self._write(self._data)

    def list_names(self) -> list[str]:
        return sorted(self._data["credentials"].keys())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_credential_store.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Stage and pause**

Run: `git add broker/credential_store.py tests/test_credential_store.py`
Then stop for operator to commit. **Per spec, confirm with operator before continuing past this task.**

---

## Task 2: policy_engine.py — load, validate, match (TDD)

**Files:**
- Create: `broker/policy_engine.py`
- Test: `tests/test_policy_engine.py`

**Interfaces:**
- Produces:
  - `class PolicyError(Exception)` — malformed policy file.
  - `@dataclass Decision` with fields `policy_name: str`, `auto_approve: bool`, `escalate: bool`.
  - `class PolicyEngine`:
    - `@classmethod from_file(path: str) -> PolicyEngine` (raises `PolicyError` on malformed YAML/schema)
    - `evaluate(self, agent: str, credential: str, now: datetime.time | None = None) -> Decision` — first match wins; falls through to a synthetic deny if no policy matches.
    - `list_policies(self) -> list[dict]` — raw policy dicts.
    - `@staticmethod validate_file(path: str) -> list[str]` — returns list of error strings (empty = valid); never raises.

- [ ] **Step 1: Write the failing test** — `tests/test_policy_engine.py`

```python
import datetime
import textwrap
import pytest
from broker.policy_engine import PolicyEngine, PolicyError


def _write(tmp_path, body):
    p = tmp_path / "policies.yaml"
    p.write_text(textwrap.dedent(body))
    return str(p)


def test_exact_match_auto_approves(tmp_path):
    path = _write(tmp_path, """
        policies:
          - name: cc-anthropic
            agent: claude-code
            credential: anthropic-api-key
            auto_approve: true
          - name: default-deny
            agent: "*"
            credential: "*"
            auto_approve: false
            escalate: true
    """)
    eng = PolicyEngine.from_file(path)
    d = eng.evaluate("claude-code", "anthropic-api-key")
    assert d.policy_name == "cc-anthropic"
    assert d.auto_approve is True


def test_wildcard_falls_through_to_default_deny(tmp_path):
    path = _write(tmp_path, """
        policies:
          - name: cc-anthropic
            agent: claude-code
            credential: anthropic-api-key
            auto_approve: true
          - name: default-deny
            agent: "*"
            credential: "*"
            auto_approve: false
            escalate: true
    """)
    eng = PolicyEngine.from_file(path)
    d = eng.evaluate("random-agent", "some-key")
    assert d.policy_name == "default-deny"
    assert d.auto_approve is False
    assert d.escalate is True


def test_time_window_inside_grants(tmp_path):
    path = _write(tmp_path, """
        policies:
          - name: daytime
            agent: claude-code
            credential: k
            auto_approve: true
            time_window: {start: "09:00", end: "17:00"}
          - name: default-deny
            agent: "*"
            credential: "*"
            auto_approve: false
            escalate: true
    """)
    eng = PolicyEngine.from_file(path)
    d = eng.evaluate("claude-code", "k", now=datetime.time(12, 0))
    assert d.policy_name == "daytime"


def test_time_window_outside_skips_to_next_policy(tmp_path):
    path = _write(tmp_path, """
        policies:
          - name: daytime
            agent: claude-code
            credential: k
            auto_approve: true
            time_window: {start: "09:00", end: "17:00"}
          - name: default-deny
            agent: "*"
            credential: "*"
            auto_approve: false
            escalate: true
    """)
    eng = PolicyEngine.from_file(path)
    d = eng.evaluate("claude-code", "k", now=datetime.time(20, 0))
    assert d.policy_name == "default-deny"


def test_time_window_wraps_past_midnight(tmp_path):
    path = _write(tmp_path, """
        policies:
          - name: overnight
            agent: a
            credential: k
            auto_approve: true
            time_window: {start: "22:00", end: "06:00"}
          - name: default-deny
            agent: "*"
            credential: "*"
            auto_approve: false
            escalate: true
    """)
    eng = PolicyEngine.from_file(path)
    assert eng.evaluate("a", "k", now=datetime.time(23, 30)).policy_name == "overnight"
    assert eng.evaluate("a", "k", now=datetime.time(3, 0)).policy_name == "overnight"
    assert eng.evaluate("a", "k", now=datetime.time(12, 0)).policy_name == "default-deny"


def test_malformed_yaml_raises_policy_error(tmp_path):
    p = tmp_path / "policies.yaml"
    p.write_text("policies: [this is : not valid")
    with pytest.raises(PolicyError):
        PolicyEngine.from_file(str(p))


def test_missing_required_field_raises_policy_error(tmp_path):
    path = _write(tmp_path, """
        policies:
          - name: broken
            agent: a
    """)
    with pytest.raises(PolicyError):
        PolicyEngine.from_file(path)


def test_no_matching_policy_and_no_default_denies(tmp_path):
    path = _write(tmp_path, """
        policies:
          - name: only
            agent: x
            credential: y
            auto_approve: true
    """)
    eng = PolicyEngine.from_file(path)
    d = eng.evaluate("other", "thing")
    assert d.auto_approve is False
    assert d.escalate is True


def test_validate_file_returns_errors_without_raising(tmp_path):
    p = tmp_path / "policies.yaml"
    p.write_text("policies:\n  - name: broken\n    agent: a\n")
    errors = PolicyEngine.validate_file(str(p))
    assert errors  # non-empty
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_policy_engine.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'broker.policy_engine'`

- [ ] **Step 3: Write `broker/policy_engine.py`**

```python
from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import List, Optional

import yaml

_REQUIRED_FIELDS = ("name", "agent", "credential", "auto_approve")


class PolicyError(Exception):
    """Raised when the policy file is malformed or fails schema validation."""


@dataclass(frozen=True)
class Decision:
    policy_name: str
    auto_approve: bool
    escalate: bool


def _parse_hhmm(value: str) -> datetime.time:
    hh, mm = value.split(":")
    return datetime.time(int(hh), int(mm))


def _in_window(now: datetime.time, start: datetime.time, end: datetime.time) -> bool:
    if start <= end:
        return start <= now <= end
    # Window wraps past midnight (e.g. 22:00–06:00).
    return now >= start or now <= end


class PolicyEngine:
    def __init__(self, policies: List[dict]) -> None:
        self._policies = policies

    @classmethod
    def from_file(cls, path: str) -> "PolicyEngine":
        errors = cls.validate_file(path)
        if errors:
            raise PolicyError("; ".join(errors))
        with open(path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        return cls(doc["policies"])

    @staticmethod
    def validate_file(path: str) -> List[str]:
        errors: List[str] = []
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
        except (OSError, yaml.YAMLError) as exc:
            return [f"could not parse policy file: {exc}"]

        if not isinstance(doc, dict) or "policies" not in doc:
            return ["policy file must have a top-level 'policies' list"]
        if not isinstance(doc["policies"], list):
            return ["'policies' must be a list"]

        for i, pol in enumerate(doc["policies"]):
            if not isinstance(pol, dict):
                errors.append(f"policy #{i} is not a mapping")
                continue
            for field in _REQUIRED_FIELDS:
                if field not in pol:
                    errors.append(f"policy '{pol.get('name', i)}' missing required field '{field}'")
            tw = pol.get("time_window")
            if tw is not None:
                if not isinstance(tw, dict) or "start" not in tw or "end" not in tw:
                    errors.append(f"policy '{pol.get('name', i)}' has malformed time_window")
                else:
                    try:
                        _parse_hhmm(tw["start"])
                        _parse_hhmm(tw["end"])
                    except (ValueError, AttributeError):
                        errors.append(f"policy '{pol.get('name', i)}' time_window must use HH:MM")
        return errors

    def list_policies(self) -> List[dict]:
        return list(self._policies)

    def evaluate(
        self, agent: str, credential: str, now: Optional[datetime.time] = None
    ) -> Decision:
        if now is None:
            now = datetime.datetime.now().time()

        for pol in self._policies:
            if not self._matches(pol, agent, credential, now):
                continue
            return Decision(
                policy_name=pol["name"],
                auto_approve=bool(pol.get("auto_approve", False)),
                escalate=bool(pol.get("escalate", not pol.get("auto_approve", False))),
            )

        # No policy matched: deny + escalate (defensive default).
        return Decision(policy_name="implicit-deny", auto_approve=False, escalate=True)

    @staticmethod
    def _matches(pol: dict, agent: str, credential: str, now: datetime.time) -> bool:
        if pol["agent"] not in ("*", agent):
            return False
        if pol["credential"] not in ("*", credential):
            return False
        tw = pol.get("time_window")
        if tw is not None:
            if not _in_window(now, _parse_hhmm(tw["start"]), _parse_hhmm(tw["end"])):
                return False
        return True
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_policy_engine.py -v`
Expected: PASS (9 passed)

- [ ] **Step 5: Stage and pause**

Run: `git add broker/policy_engine.py tests/test_policy_engine.py`
Then stop for operator to commit.

---

## Task 3: state.py — atomic mode read/write

**Files:**
- Create: `broker/state.py`
- Test: `tests/test_state.py`

**Interfaces:**
- Produces:
  - `read_mode(path: str) -> str` — returns `"auto"` or `"manual"`. If the file is missing, initializes it to `"auto"` and returns `"auto"`.
  - `write_mode(path: str, mode: str, updated_by: str = "cli") -> None` — atomic write; validates `mode in {"auto","manual"}`, else `ValueError`.
  - `toggle_mode(path: str, updated_by: str = "cli") -> str` — flips and returns the new mode.

- [ ] **Step 1: Write the failing test** — `tests/test_state.py`

```python
import json
import pytest
from broker import state


def test_read_mode_initializes_to_auto_when_missing(tmp_path):
    path = str(tmp_path / "mode.json")
    assert state.read_mode(path) == "auto"
    # File now exists with valid shape.
    data = json.loads((tmp_path / "mode.json").read_text())
    assert data["mode"] == "auto"
    assert "updated_at" in data
    assert "updated_by" in data


def test_write_then_read_round_trip(tmp_path):
    path = str(tmp_path / "mode.json")
    state.write_mode(path, "manual", updated_by="cli")
    assert state.read_mode(path) == "manual"


def test_write_rejects_invalid_mode(tmp_path):
    path = str(tmp_path / "mode.json")
    with pytest.raises(ValueError):
        state.write_mode(path, "banana")


def test_toggle_flips_mode(tmp_path):
    path = str(tmp_path / "mode.json")
    assert state.read_mode(path) == "auto"
    assert state.toggle_mode(path) == "manual"
    assert state.read_mode(path) == "manual"
    assert state.toggle_mode(path) == "auto"
    assert state.read_mode(path) == "auto"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_state.py -v`
Expected: FAIL — `ImportError: cannot import name 'state'` / attribute errors.

- [ ] **Step 3: Write `broker/state.py`**

```python
from __future__ import annotations

import datetime
import json
import os

_VALID_MODES = {"auto", "manual"}


def _now() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


def write_mode(path: str, mode: str, updated_by: str = "cli") -> None:
    if mode not in _VALID_MODES:
        raise ValueError(f"mode must be one of {_VALID_MODES}, got {mode!r}")
    payload = {"mode": mode, "updated_at": _now(), "updated_by": updated_by}
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    os.replace(tmp, path)


def read_mode(path: str) -> str:
    if not os.path.exists(path):
        write_mode(path, "auto", updated_by="init")
        return "auto"
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)["mode"]


def toggle_mode(path: str, updated_by: str = "cli") -> str:
    new_mode = "manual" if read_mode(path) == "auto" else "auto"
    write_mode(path, new_mode, updated_by=updated_by)
    return new_mode
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_state.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Stage and pause**

Run: `git add broker/state.py tests/test_state.py`
Then stop for operator to commit.

---

## Task 4: audit.py — append-only JSONL logging

**Files:**
- Create: `broker/audit.py`
- Test: `tests/test_audit.py`

**Interfaces:**
- Produces:
  - `class AuditLogger`:
    - `__init__(self, path: str)`
    - `log(self, *, agent: str, credential_requested: str, policy_matched: str, decision: str, mode: str, token_expiry: str | None) -> None` — appends one JSON line. `decision` ∈ `{"approved","denied","escalated"}`.

- [ ] **Step 1: Write the failing test** — `tests/test_audit.py`

```python
import json
from broker.audit import AuditLogger


def test_log_appends_jsonl_entry(tmp_path):
    path = str(tmp_path / "audit.log")
    logger = AuditLogger(path)
    logger.log(
        agent="claude-code",
        credential_requested="anthropic-api-key",
        policy_matched="cc-anthropic",
        decision="approved",
        mode="auto",
        token_expiry="2026-06-24T23:14:00",
    )
    lines = (tmp_path / "audit.log").read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["agent"] == "claude-code"
    assert entry["credential_requested"] == "anthropic-api-key"
    assert entry["policy_matched"] == "cc-anthropic"
    assert entry["decision"] == "approved"
    assert entry["mode"] == "auto"
    assert entry["token_expiry"] == "2026-06-24T23:14:00"
    assert "timestamp" in entry


def test_log_appends_multiple_entries(tmp_path):
    path = str(tmp_path / "audit.log")
    logger = AuditLogger(path)
    logger.log(agent="a", credential_requested="k", policy_matched="default-deny",
               decision="denied", mode="auto", token_expiry=None)
    logger.log(agent="b", credential_requested="k2", policy_matched="p",
               decision="escalated", mode="manual", token_expiry=None)
    lines = (tmp_path / "audit.log").read_text().strip().splitlines()
    assert len(lines) == 2


def test_log_never_contains_token_value(tmp_path):
    # The log() signature has no token-value parameter — only token_expiry.
    import inspect
    params = inspect.signature(AuditLogger.log).parameters
    assert "token" not in params
    assert "credential_value" not in params
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_audit.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'broker.audit'`

- [ ] **Step 3: Write `broker/audit.py`**

```python
from __future__ import annotations

import datetime
import json
import os
from typing import Optional

_VALID_DECISIONS = {"approved", "denied", "escalated"}


class AuditLogger:
    def __init__(self, path: str) -> None:
        self._path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def log(
        self,
        *,
        agent: str,
        credential_requested: str,
        policy_matched: str,
        decision: str,
        mode: str,
        token_expiry: Optional[str],
    ) -> None:
        if decision not in _VALID_DECISIONS:
            raise ValueError(f"decision must be one of {_VALID_DECISIONS}, got {decision!r}")
        entry = {
            "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
            "agent": agent,
            "credential_requested": credential_requested,
            "policy_matched": policy_matched,
            "decision": decision,
            "mode": mode,
            "token_expiry": token_expiry,
        }
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_audit.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Stage and pause**

Run: `git add broker/audit.py tests/test_audit.py`
Then stop for operator to commit.

---

## Task 5: approval.py — token issuance + escalation queue

**Files:**
- Create: `broker/approval.py`
- Test: `tests/test_approval.py`

**Interfaces:**
- Consumes: nothing directly (callers pass in TTL).
- Produces:
  - `issue_token(ttl_minutes: int, now: datetime.datetime | None = None) -> tuple[str, str]` — returns `(token, expiry_iso)`. Token is opaque (`secrets.token_urlsafe`).
  - `@dataclass PendingRequest` with `agent: str`, `credential: str`, and an `asyncio.Future` `future`.
  - `class ApprovalQueue`:
    - `async submit(self, agent: str, credential: str) -> bool` — enqueues and awaits operator decision; resolves to True/False.
    - `get_pending(self) -> PendingRequest | None` — next un-resolved request (FIFO).
    - `resolve(self, request: PendingRequest, approved: bool) -> None` — completes the future.
    - `pending_count(self) -> int`.

- [ ] **Step 1: Write the failing test** — `tests/test_approval.py`

```python
import asyncio
import datetime
import pytest
from broker.approval import issue_token, ApprovalQueue


def test_issue_token_returns_opaque_value_and_expiry():
    now = datetime.datetime(2026, 6, 24, 22, 14, 0)
    token, expiry = issue_token(60, now=now)
    assert isinstance(token, str) and len(token) >= 16
    assert expiry == "2026-06-24T23:14:00"


def test_issue_token_unique_each_call():
    t1, _ = issue_token(60)
    t2, _ = issue_token(60)
    assert t1 != t2


@pytest.mark.asyncio
async def test_submit_resolves_when_approved():
    q = ApprovalQueue()
    task = asyncio.create_task(q.submit("claude-code", "anthropic-api-key"))
    await asyncio.sleep(0)  # let submit enqueue
    pending = q.get_pending()
    assert pending is not None
    assert q.pending_count() == 1
    q.resolve(pending, True)
    assert await task is True
    assert q.pending_count() == 0


@pytest.mark.asyncio
async def test_submit_resolves_when_denied():
    q = ApprovalQueue()
    task = asyncio.create_task(q.submit("a", "k"))
    await asyncio.sleep(0)
    q.resolve(q.get_pending(), False)
    assert await task is False
```

Note: add `asyncio_mode = auto` for pytest-asyncio, OR mark tests as shown. Add `pytest-asyncio>=0.23` to `requirements.txt` and create `pytest.ini`:

```ini
[pytest]
asyncio_mode = auto
```

- [ ] **Step 2: Add dependency & config, then run test to verify it fails**

Append `pytest-asyncio>=0.23` to `requirements.txt`; create `pytest.ini` as above; run `pip install -r requirements.txt`.
Run: `pytest tests/test_approval.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'broker.approval'`

- [ ] **Step 3: Write `broker/approval.py`**

```python
from __future__ import annotations

import asyncio
import datetime
import secrets
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Optional, Tuple


def issue_token(ttl_minutes: int, now: Optional[datetime.datetime] = None) -> Tuple[str, str]:
    if now is None:
        now = datetime.datetime.now()
    token = secrets.token_urlsafe(32)
    expiry = (now + datetime.timedelta(minutes=ttl_minutes)).isoformat(timespec="seconds")
    return token, expiry


@dataclass
class PendingRequest:
    agent: str
    credential: str
    future: "asyncio.Future[bool]" = field(default=None)  # set in submit


class ApprovalQueue:
    def __init__(self) -> None:
        self._queue: Deque[PendingRequest] = deque()

    async def submit(self, agent: str, credential: str) -> bool:
        loop = asyncio.get_running_loop()
        req = PendingRequest(agent=agent, credential=credential, future=loop.create_future())
        self._queue.append(req)
        return await req.future

    def get_pending(self) -> Optional[PendingRequest]:
        for req in self._queue:
            if not req.future.done():
                return req
        return None

    def resolve(self, request: PendingRequest, approved: bool) -> None:
        if not request.future.done():
            request.future.set_result(approved)
        try:
            self._queue.remove(request)
        except ValueError:
            pass

    def pending_count(self) -> int:
        return sum(1 for r in self._queue if not r.future.done())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_approval.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Stage and pause**

Run: `git add broker/approval.py tests/test_approval.py requirements.txt pytest.ini`
Then stop for operator to commit.

---

## Task 6: mcp_server.py — broker core wired to fastmcp

**Files:**
- Create: `broker/mcp_server.py`
- Test: `tests/test_mcp_server.py`

**Interfaces:**
- Consumes: `Config`, `CredentialStore`, `PolicyEngine`, `AuditLogger`, `ApprovalQueue`, `state.read_mode`, `issue_token`.
- Produces:
  - `class Broker`: holds all components + request counters (`total_requests`, `escalated_requests`, `start_time`). This is the testable core; `mcp_server.py` exposes it and registers fastmcp tools against it.
    - `async request_credential(self, agent: str, credential: str) -> dict` — full decision flow. Returns `{"granted": bool, "token": str|None, "token_expiry": str|None, "value": str|None, "reason": str}`. Reads mode every call; manual mode always escalates; auto mode uses policy engine.
    - `list_policies(self) -> list[dict]`
    - `validate_policies(self) -> list[str]`
    - `async add_policy(self, policy: dict) -> dict` — ALWAYS escalates for human confirmation regardless of mode; returns `{"added": bool, "reason": str}`.
    - `status(self) -> dict` — `{"mode","policies","requests","escalated","uptime_seconds"}`.
  - `build_mcp(broker: Broker)` — returns a configured `FastMCP` instance with the five tools registered.

- [ ] **Step 1: Write the failing test** — `tests/test_mcp_server.py`

```python
import asyncio
import pytest
import textwrap
from broker.config import Config
from broker.credential_store import CredentialStore
from broker.policy_engine import PolicyEngine
from broker.audit import AuditLogger
from broker.approval import ApprovalQueue
from broker.mcp_server import Broker


def _make_broker(tmp_path, policy_body):
    pol = tmp_path / "policies.yaml"
    pol.write_text(textwrap.dedent(policy_body))
    env = {
        "POLICIES_PATH": str(pol),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTGATE_MASTER_PASSWORD": "pw",
    }
    cfg = Config.from_env(env)
    store = CredentialStore(cfg.credentials_path, "pw")
    store.store("anthropic-api-key", "sk-secret")
    broker = Broker(
        config=cfg,
        store=store,
        engine=PolicyEngine.from_file(cfg.policies_path),
        audit=AuditLogger(cfg.logs_path),
        approvals=ApprovalQueue(),
    )
    return broker


_AUTO_POLICY = """
    policies:
      - name: cc-anthropic
        agent: claude-code
        credential: anthropic-api-key
        auto_approve: true
      - name: default-deny
        agent: "*"
        credential: "*"
        auto_approve: false
        escalate: true
"""


@pytest.mark.asyncio
async def test_auto_approve_returns_token_and_value(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    res = await broker.request_credential("claude-code", "anthropic-api-key")
    assert res["granted"] is True
    assert res["token"]
    assert res["value"] == "sk-secret"
    assert res["token_expiry"]


@pytest.mark.asyncio
async def test_unmatched_request_escalates_then_denied(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    task = asyncio.create_task(broker.request_credential("evil", "anthropic-api-key"))
    await asyncio.sleep(0)
    pending = broker.approvals.get_pending()
    assert pending is not None
    broker.approvals.resolve(pending, False)
    res = await task
    assert res["granted"] is False
    assert res["value"] is None


@pytest.mark.asyncio
async def test_manual_mode_escalates_even_for_auto_policy(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    from broker import state
    state.write_mode(broker.config.state_path, "manual")
    task = asyncio.create_task(broker.request_credential("claude-code", "anthropic-api-key"))
    await asyncio.sleep(0)
    pending = broker.approvals.get_pending()
    assert pending is not None
    broker.approvals.resolve(pending, True)
    res = await task
    assert res["granted"] is True
    assert res["value"] == "sk-secret"


@pytest.mark.asyncio
async def test_add_policy_always_escalates(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    # Even in AUTO mode, policy.add must escalate.
    task = asyncio.create_task(broker.add_policy({
        "name": "new", "agent": "x", "credential": "y", "auto_approve": True,
    }))
    await asyncio.sleep(0)
    pending = broker.approvals.get_pending()
    assert pending is not None
    broker.approvals.resolve(pending, True)
    res = await task
    assert res["added"] is True


def test_status_reports_mode_and_counts(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    s = broker.status()
    assert s["mode"] in ("auto", "manual")
    assert s["policies"] == 2
    assert s["requests"] == 0
    assert "uptime_seconds" in s
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_mcp_server.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'broker.mcp_server'`

- [ ] **Step 3: Write `broker/mcp_server.py`**

```python
from __future__ import annotations

import datetime
from typing import List, Optional

from fastmcp import FastMCP

from broker import state
from broker.approval import ApprovalQueue, issue_token
from broker.audit import AuditLogger
from broker.config import Config
from broker.credential_store import CredentialStore
from broker.policy_engine import PolicyEngine, PolicyError


class Broker:
    def __init__(
        self,
        *,
        config: Config,
        store: CredentialStore,
        engine: PolicyEngine,
        audit: AuditLogger,
        approvals: ApprovalQueue,
    ) -> None:
        self.config = config
        self.store = store
        self.engine = engine
        self.audit = audit
        self.approvals = approvals
        self.total_requests = 0
        self.escalated_requests = 0
        self.start_time = datetime.datetime.now()

    async def request_credential(self, agent: str, credential: str) -> dict:
        self.total_requests += 1
        mode = state.read_mode(self.config.state_path)

        if mode == "manual":
            return await self._escalate(agent, credential, mode, policy_name="manual-mode")

        decision = self.engine.evaluate(agent, credential)
        if decision.auto_approve:
            return self._grant(agent, credential, mode, decision.policy_name)
        return await self._escalate(agent, credential, mode, decision.policy_name)

    def _grant(self, agent: str, credential: str, mode: str, policy_name: str) -> dict:
        try:
            value = self.store.retrieve(credential)
        except KeyError:
            self.audit.log(agent=agent, credential_requested=credential,
                           policy_matched=policy_name, decision="denied",
                           mode=mode, token_expiry=None)
            return {"granted": False, "token": None, "token_expiry": None,
                    "value": None, "reason": f"unknown credential '{credential}'"}
        token, expiry = issue_token(self.config.token_ttl_minutes)
        self.audit.log(agent=agent, credential_requested=credential,
                       policy_matched=policy_name, decision="approved",
                       mode=mode, token_expiry=expiry)
        return {"granted": True, "token": token, "token_expiry": expiry,
                "value": value, "reason": f"auto-approved by policy '{policy_name}'"}

    async def _escalate(self, agent: str, credential: str, mode: str, policy_name: str) -> dict:
        self.escalated_requests += 1
        self.audit.log(agent=agent, credential_requested=credential,
                       policy_matched=policy_name, decision="escalated",
                       mode=mode, token_expiry=None)
        approved = await self.approvals.submit(agent, credential)
        if approved:
            return self._grant(agent, credential, mode, f"manual:{policy_name}")
        self.audit.log(agent=agent, credential_requested=credential,
                       policy_matched=policy_name, decision="denied",
                       mode=mode, token_expiry=None)
        return {"granted": False, "token": None, "token_expiry": None,
                "value": None, "reason": "denied by operator"}

    def list_policies(self) -> List[dict]:
        return self.engine.list_policies()

    def validate_policies(self) -> List[str]:
        return PolicyEngine.validate_file(self.config.policies_path)

    async def add_policy(self, policy: dict) -> dict:
        # Hard rule: policy mutation ALWAYS escalates, regardless of mode/policy.
        approved = await self.approvals.submit("SYSTEM", f"policy.add:{policy.get('name')}")
        if not approved:
            return {"added": False, "reason": "policy change denied by operator"}
        import yaml
        with open(self.config.policies_path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {"policies": []}
        doc["policies"].insert(0, policy)
        tmp = f"{self.config.policies_path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            yaml.safe_dump(doc, fh)
        import os
        os.replace(tmp, self.config.policies_path)
        self.engine = PolicyEngine.from_file(self.config.policies_path)
        return {"added": True, "reason": f"policy '{policy.get('name')}' added"}

    def status(self) -> dict:
        return {
            "mode": state.read_mode(self.config.state_path),
            "policies": len(self.engine.list_policies()),
            "requests": self.total_requests,
            "escalated": self.escalated_requests,
            "uptime_seconds": int((datetime.datetime.now() - self.start_time).total_seconds()),
        }


def build_mcp(broker: Broker) -> FastMCP:
    mcp = FastMCP("AgentGate")

    @mcp.tool(name="credential.request")
    async def credential_request(agent: str, credential: str) -> dict:
        return await broker.request_credential(agent, credential)

    @mcp.tool(name="policy.list")
    def policy_list() -> List[dict]:
        return broker.list_policies()

    @mcp.tool(name="policy.validate")
    def policy_validate() -> dict:
        errors = broker.validate_policies()
        return {"valid": not errors, "errors": errors}

    @mcp.tool(name="policy.add")
    async def policy_add(policy: dict) -> dict:
        return await broker.add_policy(policy)

    @mcp.tool(name="broker.status")
    def broker_status() -> dict:
        return broker.status()

    return mcp
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_mcp_server.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Stage and pause**

Run: `git add broker/mcp_server.py tests/test_mcp_server.py`
Then stop for operator to commit.

---

## Task 7: main.py — async CLI tying it together

**Files:**
- Create: `broker/main.py`
- Test: `tests/test_main.py` (covers the non-IO helpers; the stdin loop is integration-tested manually)

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `resolve_master_password(config: Config) -> str` — returns `config.master_password` or prompts via `getpass`.
  - `build_broker(config: Config, master_password: str) -> Broker` — constructs all components.
  - `format_status_line(broker: Broker) -> str` — the `[AgentGate] running in ... mode | policies: N | requests: N | escalated: N` string.
  - `async run(config: Config | None = None) -> None` — entry point: builds broker, starts MCP server task + CLI input task. Module is runnable via `python -m broker.main`.

- [ ] **Step 1: Write the failing test** — `tests/test_main.py`

```python
import textwrap
from broker.config import Config
from broker import main as main_mod


def _cfg(tmp_path):
    pol = tmp_path / "policies.yaml"
    pol.write_text(textwrap.dedent("""
        policies:
          - name: default-deny
            agent: "*"
            credential: "*"
            auto_approve: false
            escalate: true
    """))
    return Config.from_env({
        "POLICIES_PATH": str(pol),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTGATE_MASTER_PASSWORD": "pw",
    })


def test_resolve_master_password_prefers_env(tmp_path):
    assert main_mod.resolve_master_password(_cfg(tmp_path)) == "pw"


def test_build_broker_constructs_with_policies(tmp_path):
    cfg = _cfg(tmp_path)
    broker = main_mod.build_broker(cfg, "pw")
    assert broker.status()["policies"] == 1


def test_format_status_line_contains_mode_and_counts(tmp_path):
    cfg = _cfg(tmp_path)
    broker = main_mod.build_broker(cfg, "pw")
    line = main_mod.format_status_line(broker)
    assert "AgentGate" in line
    assert "policies: 1" in line
    assert "requests: 0" in line
    assert "escalated: 0" in line
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_main.py -v`
Expected: FAIL — `AttributeError` / `ModuleNotFoundError`.

- [ ] **Step 3: Write `broker/main.py`**

```python
from __future__ import annotations

import asyncio
import getpass
import sys

from broker import state
from broker.approval import ApprovalQueue
from broker.audit import AuditLogger
from broker.config import Config
from broker.credential_store import CredentialStore
from broker.mcp_server import Broker, build_mcp


def resolve_master_password(config: Config) -> str:
    if config.master_password:
        return config.master_password
    return getpass.getpass("AgentGate master password: ")


def build_broker(config: Config, master_password: str) -> Broker:
    store = CredentialStore(config.credentials_path, master_password)
    from broker.policy_engine import PolicyEngine
    return Broker(
        config=config,
        store=store,
        engine=PolicyEngine.from_file(config.policies_path),
        audit=AuditLogger(config.logs_path),
        approvals=ApprovalQueue(),
    )


def format_status_line(broker: Broker) -> str:
    s = broker.status()
    return (
        f"[AgentGate] running in {s['mode'].upper()} mode | "
        f"policies: {s['policies']} | requests: {s['requests']} | "
        f"escalated: {s['escalated']}"
    )


async def _cli_loop(broker: Broker) -> None:
    loop = asyncio.get_running_loop()
    print(format_status_line(broker))
    while True:
        # Surface any pending approval first.
        pending = broker.approvals.get_pending()
        if pending is not None:
            prompt = (
                f"[AgentGate] pending approval: {pending.agent} "
                f"requesting {pending.credential} [y/n]: "
            )
            answer = await loop.run_in_executor(None, input, prompt)
            broker.approvals.resolve(pending, answer.strip().lower().startswith("y"))
            continue
        answer = await loop.run_in_executor(None, input, "[AgentGate] >> ")
        cmd = answer.strip().lower()
        if cmd == "s":
            new_mode = state.toggle_mode(broker.config.state_path)
            print(f"[AgentGate] switched to {new_mode.upper()} mode")
        elif cmd in ("q", "quit", "exit"):
            print("[AgentGate] shutting down")
            return
        else:
            print(format_status_line(broker))


async def run(config: Config | None = None) -> None:
    config = config or Config.from_env()
    master_password = resolve_master_password(config)
    broker = build_broker(config, master_password)
    mcp = build_mcp(broker)

    cli_task = asyncio.create_task(_cli_loop(broker))
    server_task = asyncio.create_task(mcp.run_async())
    done, pending = await asyncio.wait(
        {cli_task, server_task}, return_when=asyncio.FIRST_COMPLETED
    )
    for task in pending:
        task.cancel()


def main() -> None:
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\n[AgentGate] interrupted", file=sys.stderr)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_main.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Stage and pause**

Run: `git add broker/main.py tests/test_main.py`
Then stop for operator to commit.

---

## Task 8: cli/commands.py — standalone operator commands

**Files:**
- Create: `cli/commands.py`
- Test: `tests/test_cli_commands.py`

**Interfaces:**
- Consumes: `Config`, `CredentialStore`, `PolicyEngine`, `state`.
- Produces: `build_parser() -> argparse.ArgumentParser` and `run(argv: list[str], config: Config | None = None, master_password: str | None = None) -> int`. Subcommands:
  - `cred-store <name>` (reads value from `AGENTGATE_CRED_VALUE` env or stdin), `cred-delete <name>`, `cred-list`
  - `policy-validate`
  - `status`
  Returns process exit code (0 ok, non-zero on error). Runnable via `python -m cli.commands`.

- [ ] **Step 1: Write the failing test** — `tests/test_cli_commands.py`

```python
import textwrap
from broker.config import Config
from cli import commands


def _cfg(tmp_path):
    pol = tmp_path / "policies.yaml"
    pol.write_text(textwrap.dedent("""
        policies:
          - name: default-deny
            agent: "*"
            credential: "*"
            auto_approve: false
            escalate: true
    """))
    return Config.from_env({
        "POLICIES_PATH": str(pol),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
    })


def test_cred_store_list_delete(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path)
    monkeypatch.setenv("AGENTGATE_CRED_VALUE", "sk-secret")
    assert commands.run(["cred-store", "k"], config=cfg, master_password="pw") == 0
    assert commands.run(["cred-list"], config=cfg, master_password="pw") == 0
    out = capsys.readouterr().out
    assert "k" in out
    assert "sk-secret" not in out  # value never printed
    assert commands.run(["cred-delete", "k"], config=cfg, master_password="pw") == 0


def test_policy_validate_ok(tmp_path):
    cfg = _cfg(tmp_path)
    assert commands.run(["policy-validate"], config=cfg) == 0


def test_status_prints_mode(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    assert commands.run(["status"], config=cfg) == 0
    assert "auto" in capsys.readouterr().out.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli_commands.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cli.commands'`

- [ ] **Step 3: Write `cli/commands.py`**

```python
from __future__ import annotations

import argparse
import getpass
import os
import sys
from typing import List, Optional

from broker import state
from broker.config import Config
from broker.credential_store import CredentialStore
from broker.policy_engine import PolicyEngine


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentgate", description="AgentGate operator CLI")
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("cred-store", help="store a credential")
    s.add_argument("name")
    d = sub.add_parser("cred-delete", help="delete a credential")
    d.add_argument("name")
    sub.add_parser("cred-list", help="list credential names")
    sub.add_parser("policy-validate", help="validate the policy file")
    sub.add_parser("status", help="print broker status")
    return parser


def _password(master_password: Optional[str]) -> str:
    if master_password:
        return master_password
    env = os.environ.get("AGENTGATE_MASTER_PASSWORD")
    if env:
        return env
    return getpass.getpass("AgentGate master password: ")


def run(
    argv: List[str],
    config: Optional[Config] = None,
    master_password: Optional[str] = None,
) -> int:
    config = config or Config.from_env()
    args = build_parser().parse_args(argv)

    if args.command == "cred-store":
        value = os.environ.get("AGENTGATE_CRED_VALUE") or sys.stdin.readline().rstrip("\n")
        CredentialStore(config.credentials_path, _password(master_password)).store(args.name, value)
        print(f"stored credential '{args.name}'")
        return 0

    if args.command == "cred-delete":
        try:
            CredentialStore(config.credentials_path, _password(master_password)).delete(args.name)
        except KeyError:
            print(f"no such credential '{args.name}'", file=sys.stderr)
            return 1
        print(f"deleted credential '{args.name}'")
        return 0

    if args.command == "cred-list":
        names = CredentialStore(config.credentials_path, _password(master_password)).list_names()
        for name in names:
            print(name)
        return 0

    if args.command == "policy-validate":
        errors = PolicyEngine.validate_file(config.policies_path)
        if errors:
            for e in errors:
                print(f"INVALID: {e}", file=sys.stderr)
            return 1
        print("policy file is valid")
        return 0

    if args.command == "status":
        print(f"mode: {state.read_mode(config.state_path)}")
        print(f"policies: {len(PolicyEngine.from_file(config.policies_path).list_policies())}")
        return 0

    return 2


def main() -> None:
    raise SystemExit(run(sys.argv[1:]))


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli_commands.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Run the full suite**

Run: `pytest -v`
Expected: all tests pass.

- [ ] **Step 6: Stage and pause**

Run: `git add cli/commands.py tests/test_cli_commands.py`
Then stop for operator to commit.

---

## Task 9: Packaging — seed files, Docker, README

**Files:**
- Create: `policies/policies.yaml`, `state/.gitkeep`, `logs/.gitkeep`, `data/.gitkeep`
- Create: `Dockerfile`, `docker-compose.yml`, `README.md`

**Interfaces:** none (packaging only).

- [ ] **Step 1: Seed `policies/policies.yaml`**

```yaml
policies:
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

- [ ] **Step 2: Create volume keep-files**

Create empty `state/.gitkeep`, `logs/.gitkeep`, `data/.gitkeep`.

- [ ] **Step 3: Write `Dockerfile`**

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY broker/ broker/
COPY cli/ cli/
CMD ["python", "-m", "broker.main"]
```

- [ ] **Step 4: Write `docker-compose.yml`**

```yaml
services:
  agentgate:
    build: .
    stdin_open: true
    tty: true
    env_file: .env
    environment:
      POLICIES_PATH: /app/policies/policies.yaml
      STATE_PATH: /app/state/mode.json
      LOGS_PATH: /app/logs/audit.log
      CREDENTIALS_PATH: /app/data/credentials.json
    volumes:
      - ./policies:/app/policies
      - ./state:/app/state
      - ./logs:/app/logs
      - ./data:/app/data
```

- [ ] **Step 5: Write `README.md`**

Document: what AgentGate is, V1 scope, quickstart (`pip install -r requirements.txt`, `cp .env.example .env`, set `AGENTGATE_MASTER_PASSWORD`, seed a credential via `python -m cli.commands cred-store anthropic-api-key`, run `python -m broker.main` or `docker compose up`), the policy schema, MCP tools, the AUTO/MANUAL toggle (`s`), audit log location, and the ECS migration note (all state on mounted volumes via env paths).

- [ ] **Step 6: Verify the container builds and tests pass**

Run: `docker compose build` (expected: builds clean) and `pytest -v` (expected: all pass).

- [ ] **Step 7: Stage and pause**

Run: `git add policies/ state/.gitkeep logs/.gitkeep data/.gitkeep Dockerfile docker-compose.yml README.md`
Then stop for operator to commit.

---

## Self-Review

**Spec coverage:**
- API keys only ✓ (credential_store) · YAML policy engine ✓ (Task 2) · two-tier approval ✓ (Task 6 `_grant`/`_escalate`) · runtime mode toggle to state file ✓ (Task 3 + Task 7 `s` key) · fastmcp server ✓ (Task 6 `build_mcp`) · audit logging ✓ (Task 4) · async CLI ✓ (Task 7) · Docker Compose + mounted volumes ✓ (Task 9).
- Mode read every request, never cached ✓ (`request_credential` calls `state.read_mode`). · Credentials never logged ✓ (audit signature has no value/token param; test asserts it). · `policy.add` always escalates ✓ (Task 6 + test). · All paths from env ✓ (Task 0 `Config`). · Argon2id + AES-256-GCM + salt persistence + per-cred nonce ✓ (Task 1). · Token TTL configurable ✓ (`TOKEN_TTL_MINUTES`). · Master password env→getpass ✓ (Task 7).

**Placeholder scan:** README step describes content rather than pasting the full file — acceptable (prose doc, not code). All code steps contain complete, runnable code.

**Type consistency:** `Config` fields, `Decision`, `CredentialStore`/`CredentialDecryptionError`, `AuditLogger.log` kwargs, `ApprovalQueue`/`PendingRequest`, and `Broker` method signatures are used identically across tasks. `request_credential` return dict shape (`granted/token/token_expiry/value/reason`) is consistent between Task 6 impl and tests.

**Note on `policy.add` escalation surfacing:** policy-change approvals share the `ApprovalQueue`; the CLI prompt shows them as `SYSTEM requesting policy.add:<name>`. Functional and audited; a dedicated prompt string is a possible future polish (out of V1 scope).
