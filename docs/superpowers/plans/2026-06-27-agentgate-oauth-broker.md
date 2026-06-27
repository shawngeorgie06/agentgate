# AgentGate OAuth Broker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an OAuth 2.0 broker to AgentGate so an operator can `connect` a provider account once and agents can then request a named connection over MCP to receive a fresh, short-lived, scoped access token minted from a refresh token they never see.

**Architecture:** Reuse V1's policy engine, AUTO/MANUAL state, escalation queue, and audit logger unchanged. Add a shared crypto module, an encrypted connections store, a pure OAuth module (PKCE auth-code flow + token exchange/refresh/revoke + a localhost callback server), a `request_token` path on the existing `Broker`, a `token.request` MCP tool, and `connect`/`connections`/`disconnect` operator CLI commands.

**Tech Stack:** Python 3.11+, `fastmcp`, `httpx` (async HTTP), `cryptography` (AES-256-GCM), `argon2-cffi` (Argon2id), `PyYAML`, `pytest` + `pytest-asyncio` (`asyncio_mode = auto`).

## Global Constraints

- The operator's password is never stored and never transits AgentGate — only the resulting refresh token is stored, encrypted at rest.
- Refresh tokens, client secrets, and authorization codes are never returned to an agent and never written to the audit log or error messages. Only short-lived access tokens are released to agents.
- Mode is read on every request via `state.read_mode(config.state_path)`, never cached. MANUAL mode escalates every `token.request` regardless of policy.
- Policy governs `token.request` identically to V1 credential requests: match on agent + connection name → auto-approve / escalate / deny. An agent can never modify the policy governing its own access.
- All store/state/log paths are configurable via environment variables; no hardcoded paths in application code.
- PKCE (RFC 7636, S256) is mandatory on the authorization-code flow. The `state` parameter is validated on callback.
- The OAuth redirect URI is fixed and env-configurable (`http://localhost:<OAUTH_REDIRECT_PORT>/callback`, default port `8765`) so it matches what the operator registered in their OAuth app — never a random port.
- All Python modules begin with `from __future__ import annotations` (matches V1).
- Existing V1 behavior and tests must remain green; new fields/params are added backward-compatibly.

---

### Task 1: Shared crypto module

Extract V1's AES-256-GCM + Argon2id primitives into a reusable module so the new connections store and the existing credential store share one implementation (DRY: Argon2 parameters must not be duplicated across two files).

**Files:**
- Create: `broker/crypto.py`
- Modify: `broker/credential_store.py` (refactor to use `broker/crypto.py`, behavior-neutral)
- Test: `tests/test_crypto.py`

**Interfaces:**
- Consumes: nothing (leaf module).
- Produces:
  - `b64e(raw: bytes) -> str`, `b64d(text: str) -> bytes`
  - `new_salt() -> str` (base64 of 16 random bytes)
  - `derive_key(password: str, salt_b64: str) -> bytes` (32-byte Argon2id key)
  - `encrypt(key: bytes, plaintext: str) -> dict` → `{"nonce": str, "ciphertext": str}`
  - `decrypt(key: bytes, entry: dict) -> str` (raises `CryptoDecryptionError` on bad key/tamper)
  - `class CryptoDecryptionError(Exception)`

- [ ] **Step 1: Write the failing test**

Create `tests/test_crypto.py`:

```python
from __future__ import annotations

import pytest

from broker import crypto


def test_roundtrip_encrypt_decrypt():
    salt = crypto.new_salt()
    key = crypto.derive_key("master-pw", salt)
    entry = crypto.encrypt(key, "s3cret-value")
    assert entry["nonce"] and entry["ciphertext"]
    assert "s3cret-value" not in entry["ciphertext"]
    assert crypto.decrypt(key, entry) == "s3cret-value"


def test_wrong_password_raises():
    salt = crypto.new_salt()
    entry = crypto.encrypt(crypto.derive_key("right-pw", salt), "v")
    wrong_key = crypto.derive_key("wrong-pw", salt)
    with pytest.raises(crypto.CryptoDecryptionError):
        crypto.decrypt(wrong_key, entry)


def test_new_salt_is_random():
    assert crypto.new_salt() != crypto.new_salt()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_crypto.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'broker.crypto'`

- [ ] **Step 3: Write the implementation**

Create `broker/crypto.py`:

```python
from __future__ import annotations

import base64
import os

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


class CryptoDecryptionError(Exception):
    """Raised when ciphertext cannot be decrypted (wrong key or tampering)."""


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def new_salt() -> str:
    return b64e(os.urandom(_SALT_LEN))


def derive_key(password: str, salt_b64: str) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=b64d(salt_b64),
        time_cost=_ARGON2_TIME_COST,
        memory_cost=_ARGON2_MEMORY_COST,
        parallelism=_ARGON2_PARALLELISM,
        hash_len=_KEY_LEN,
        type=Type.ID,
    )


def encrypt(key: bytes, plaintext: str) -> dict:
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return {"nonce": b64e(nonce), "ciphertext": b64e(ciphertext)}


def decrypt(key: bytes, entry: dict) -> str:
    try:
        plaintext = AESGCM(key).decrypt(b64d(entry["nonce"]), b64d(entry["ciphertext"]), None)
    except InvalidTag as exc:
        raise CryptoDecryptionError("could not decrypt (wrong password or tampered store)") from exc
    return plaintext.decode("utf-8")
```

- [ ] **Step 4: Run the new test to verify it passes**

Run: `python -m pytest tests/test_crypto.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Refactor `credential_store.py` to use `crypto.py` (behavior-neutral)**

Replace the body of `broker/credential_store.py` with this version (same public API and on-disk format; crypto delegated to `broker.crypto`):

```python
from __future__ import annotations

import json
import os

from broker import crypto


class CredentialDecryptionError(Exception):
    """Raised when a credential cannot be decrypted (wrong key or tampering)."""


class CredentialStore:
    def __init__(self, path: str, master_password: str) -> None:
        self._path = path
        self._password = master_password
        is_new = not os.path.exists(self._path)
        self._data = self._load()
        self._key = crypto.derive_key(self._password, self._data["salt"])
        if is_new:
            self._write(self._data)

    def _load(self) -> dict:
        if os.path.exists(self._path):
            with open(self._path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        return {"salt": crypto.new_salt(), "credentials": {}}

    def _write(self, data: dict) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self._path)), exist_ok=True)
        tmp = f"{self._path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, self._path)

    def store(self, name: str, value: str) -> None:
        self._data["credentials"][name] = crypto.encrypt(self._key, value)
        self._write(self._data)

    def retrieve(self, name: str) -> str:
        if name not in self._data["credentials"]:
            raise KeyError(name)
        try:
            return crypto.decrypt(self._key, self._data["credentials"][name])
        except crypto.CryptoDecryptionError as exc:
            raise CredentialDecryptionError(
                f"could not decrypt credential '{name}' (wrong password or tampered store)"
            ) from exc

    def delete(self, name: str) -> None:
        if name not in self._data["credentials"]:
            raise KeyError(name)
        del self._data["credentials"][name]
        self._write(self._data)

    def list_names(self) -> list[str]:
        return sorted(self._data["credentials"].keys())
```

- [ ] **Step 6: Run the full suite to prove no regression**

Run: `python -m pytest tests/test_crypto.py tests/test_credential_store.py -v`
Expected: PASS (all existing credential_store tests + 3 new crypto tests)

- [ ] **Step 7: Commit**

```bash
git add broker/crypto.py broker/credential_store.py tests/test_crypto.py
git commit -m "refactor: extract shared crypto module; reuse in credential store"
```

---

### Task 2: Connections store

Encrypted persistence for OAuth connections. Client secret and refresh token are encrypted; provider, client ID, scopes, and created-at are stored in clear for listing (client ID is public; the others are non-secret metadata).

**Files:**
- Create: `broker/connection_store.py`
- Test: `tests/test_connection_store.py`

**Interfaces:**
- Consumes: `broker.crypto` (`new_salt`, `derive_key`, `encrypt`, `decrypt`).
- Produces:
  - `@dataclass(frozen=True) class Connection: provider: str; client_id: str; client_secret: str; refresh_token: str; scopes: list[str]; created_at: str`
  - `class ConnectionStore:`
    - `__init__(self, path: str, master_password: str)`
    - `store(self, name: str, conn: Connection) -> None`
    - `get(self, name: str) -> Connection` (raises `KeyError`)
    - `delete(self, name: str) -> None` (raises `KeyError`)
    - `list_names(self) -> list[str]`
    - `list_metadata(self) -> list[dict]` → `[{"name", "provider", "scopes", "created_at"}]` (no secrets)

- [ ] **Step 1: Write the failing test**

Create `tests/test_connection_store.py`:

```python
from __future__ import annotations

import pytest

from broker.connection_store import Connection, ConnectionStore


def _conn() -> Connection:
    return Connection(
        provider="google",
        client_id="cid-123",
        client_secret="csecret-xyz",
        refresh_token="rt-abc",
        scopes=["openid", "email"],
        created_at="2026-06-27T10:00:00",
    )


def test_store_and_get_roundtrip(tmp_path):
    store = ConnectionStore(str(tmp_path / "connections.json"), "pw")
    store.store("work", _conn())
    got = store.get("work")
    assert got.provider == "google"
    assert got.client_secret == "csecret-xyz"
    assert got.refresh_token == "rt-abc"
    assert got.scopes == ["openid", "email"]


def test_secrets_not_plaintext_on_disk(tmp_path):
    path = tmp_path / "connections.json"
    ConnectionStore(str(path), "pw").store("work", _conn())
    raw = path.read_text(encoding="utf-8")
    assert "csecret-xyz" not in raw
    assert "rt-abc" not in raw


def test_list_metadata_has_no_secrets(tmp_path):
    store = ConnectionStore(str(tmp_path / "connections.json"), "pw")
    store.store("work", _conn())
    meta = store.list_metadata()
    assert meta == [
        {"name": "work", "provider": "google", "scopes": ["openid", "email"],
         "created_at": "2026-06-27T10:00:00"}
    ]


def test_delete_and_missing(tmp_path):
    store = ConnectionStore(str(tmp_path / "connections.json"), "pw")
    store.store("work", _conn())
    store.delete("work")
    assert store.list_names() == []
    with pytest.raises(KeyError):
        store.get("work")
    with pytest.raises(KeyError):
        store.delete("work")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_connection_store.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'broker.connection_store'`

- [ ] **Step 3: Write the implementation**

Create `broker/connection_store.py`:

```python
from __future__ import annotations

import json
import os
from dataclasses import dataclass

from broker import crypto


@dataclass(frozen=True)
class Connection:
    provider: str
    client_id: str
    client_secret: str
    refresh_token: str
    scopes: list[str]
    created_at: str


class ConnectionStore:
    def __init__(self, path: str, master_password: str) -> None:
        self._path = path
        is_new = not os.path.exists(self._path)
        self._data = self._load()
        self._key = crypto.derive_key(master_password, self._data["salt"])
        if is_new:
            self._write(self._data)

    def _load(self) -> dict:
        if os.path.exists(self._path):
            with open(self._path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        return {"salt": crypto.new_salt(), "connections": {}}

    def _write(self, data: dict) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self._path)), exist_ok=True)
        tmp = f"{self._path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, self._path)

    def store(self, name: str, conn: Connection) -> None:
        self._data["connections"][name] = {
            "provider": conn.provider,
            "client_id": conn.client_id,
            "client_secret": crypto.encrypt(self._key, conn.client_secret),
            "refresh_token": crypto.encrypt(self._key, conn.refresh_token),
            "scopes": list(conn.scopes),
            "created_at": conn.created_at,
        }
        self._write(self._data)

    def get(self, name: str) -> Connection:
        if name not in self._data["connections"]:
            raise KeyError(name)
        rec = self._data["connections"][name]
        return Connection(
            provider=rec["provider"],
            client_id=rec["client_id"],
            client_secret=crypto.decrypt(self._key, rec["client_secret"]),
            refresh_token=crypto.decrypt(self._key, rec["refresh_token"]),
            scopes=list(rec["scopes"]),
            created_at=rec["created_at"],
        )

    def delete(self, name: str) -> None:
        if name not in self._data["connections"]:
            raise KeyError(name)
        del self._data["connections"][name]
        self._write(self._data)

    def list_names(self) -> list[str]:
        return sorted(self._data["connections"].keys())

    def list_metadata(self) -> list[dict]:
        return [
            {
                "name": name,
                "provider": rec["provider"],
                "scopes": list(rec["scopes"]),
                "created_at": rec["created_at"],
            }
            for name, rec in sorted(self._data["connections"].items())
        ]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_connection_store.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add broker/connection_store.py tests/test_connection_store.py
git commit -m "feat: encrypted OAuth connections store"
```

---

### Task 3: Config additions

Add `connections_path` and `oauth_redirect_port` to `Config`, with env defaults and validation, backward-compatibly.

**Files:**
- Modify: `broker/config.py`
- Test: `tests/test_config.py` (append cases)

**Interfaces:**
- Consumes: existing `Config.from_env`, `_require_int`, `_require_non_empty`.
- Produces: `Config.connections_path: str` (env `CONNECTIONS_PATH`, default `data/connections.json`), `Config.oauth_redirect_port: int` (env `OAUTH_REDIRECT_PORT`, default `8765`, must be a positive integer).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_config.py`:

```python
def test_oauth_defaults():
    from broker.config import Config
    env = {
        "POLICIES_PATH": "p", "STATE_PATH": "s", "LOGS_PATH": "l",
        "CREDENTIALS_PATH": "c",
    }
    cfg = Config.from_env(env)
    assert cfg.connections_path.endswith("connections.json")
    assert cfg.oauth_redirect_port == 8765


def test_oauth_redirect_port_override_and_validation():
    import pytest
    from broker.config import Config, ConfigError
    base = {
        "POLICIES_PATH": "p", "STATE_PATH": "s", "LOGS_PATH": "l",
        "CREDENTIALS_PATH": "c",
    }
    assert Config.from_env({**base, "OAUTH_REDIRECT_PORT": "9000"}).oauth_redirect_port == 9000
    with pytest.raises(ConfigError):
        Config.from_env({**base, "OAUTH_REDIRECT_PORT": "0"})
    with pytest.raises(ConfigError):
        Config.from_env({**base, "OAUTH_REDIRECT_PORT": "notaport"})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_config.py -k oauth -v`
Expected: FAIL with `AttributeError: 'Config' object has no attribute 'connections_path'`

- [ ] **Step 3: Write the implementation**

In `broker/config.py`, add two entries to `_DEFAULTS` (after `CREDENTIALS_PATH`):

```python
    "CONNECTIONS_PATH": os.path.join("data", "connections.json"),
    "OAUTH_REDIRECT_PORT": "8765",
```

Add two fields to the `Config` dataclass, after `master_password`, with defaults (so direct constructors in existing tests keep working):

```python
    connections_path: str = os.path.join("data", "connections.json")
    oauth_redirect_port: int = 8765
```

In `from_env`, add to the `cls(...)` call (after `master_password=...`):

```python
            connections_path=_require_non_empty(get("CONNECTIONS_PATH"), "CONNECTIONS_PATH"),
            oauth_redirect_port=_require_int(
                get("OAUTH_REDIRECT_PORT"), "OAUTH_REDIRECT_PORT", minimum=1
            ),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_config.py -v`
Expected: PASS (existing config tests + new oauth tests)

- [ ] **Step 5: Commit**

```bash
git add broker/config.py tests/test_config.py
git commit -m "feat: config for connections path and oauth redirect port"
```

---

### Task 4: OAuth pure helpers (presets, PKCE, auth URL)

The network-free core of the OAuth module: provider presets, PKCE generation, and authorization-URL construction.

**Files:**
- Create: `broker/oauth.py`
- Test: `tests/test_oauth_helpers.py`

**Interfaces:**
- Consumes: nothing (stdlib only).
- Produces:
  - `class OAuthError(Exception)`
  - `@dataclass(frozen=True) class ProviderPreset: auth_url: str; token_url: str; revoke_url: str | None; default_scopes: list[str]`
  - `PRESETS: dict[str, ProviderPreset]` with keys `"google"`, `"github"`
  - `get_preset(provider: str) -> ProviderPreset` (raises `OAuthError` for unknown provider)
  - `generate_pkce() -> tuple[str, str]` returns `(verifier, challenge)` where challenge is base64url-S256 of the verifier
  - `build_auth_url(*, preset: ProviderPreset, client_id: str, redirect_uri: str, scopes: list[str], state: str, challenge: str) -> str`

- [ ] **Step 1: Write the failing test**

Create `tests/test_oauth_helpers.py`:

```python
from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import pytest

from broker import oauth


def test_get_preset_known_and_unknown():
    assert oauth.get_preset("google").token_url.startswith("https://")
    assert oauth.get_preset("github").auth_url.startswith("https://")
    with pytest.raises(oauth.OAuthError):
        oauth.get_preset("nope")


def test_generate_pkce_s256():
    verifier, challenge = oauth.generate_pkce()
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    assert challenge == expected
    assert 43 <= len(verifier) <= 128


def test_build_auth_url_contains_params():
    preset = oauth.get_preset("google")
    url = oauth.build_auth_url(
        preset=preset,
        client_id="cid",
        redirect_uri="http://localhost:8765/callback",
        scopes=["openid", "email"],
        state="st8",
        challenge="chal",
    )
    q = parse_qs(urlparse(url).query)
    assert q["client_id"] == ["cid"]
    assert q["redirect_uri"] == ["http://localhost:8765/callback"]
    assert q["state"] == ["st8"]
    assert q["code_challenge"] == ["chal"]
    assert q["code_challenge_method"] == ["S256"]
    assert q["response_type"] == ["code"]
    assert q["scope"] == ["openid email"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_oauth_helpers.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'broker.oauth'`

- [ ] **Step 3: Write the implementation**

Create `broker/oauth.py`:

```python
from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from urllib.parse import urlencode


class OAuthError(Exception):
    """Raised on OAuth protocol or configuration errors."""


@dataclass(frozen=True)
class ProviderPreset:
    auth_url: str
    token_url: str
    revoke_url: str | None
    default_scopes: list[str]


PRESETS: dict[str, ProviderPreset] = {
    "google": ProviderPreset(
        auth_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        revoke_url="https://oauth2.googleapis.com/revoke",
        default_scopes=["openid", "email", "profile"],
    ),
    "github": ProviderPreset(
        auth_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        revoke_url=None,
        default_scopes=["read:user"],
    ),
}


def get_preset(provider: str) -> ProviderPreset:
    try:
        return PRESETS[provider]
    except KeyError:
        raise OAuthError(f"unknown provider '{provider}'; known: {sorted(PRESETS)}") from None


def generate_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:96]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def build_auth_url(
    *,
    preset: ProviderPreset,
    client_id: str,
    redirect_uri: str,
    scopes: list[str],
    state: str,
    challenge: str,
) -> str:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "consent",
    }
    return f"{preset.auth_url}?{urlencode(params)}"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_oauth_helpers.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add broker/oauth.py tests/test_oauth_helpers.py
git commit -m "feat: oauth presets, PKCE, and authorization URL builder"
```

---

### Task 5: OAuth token exchange, refresh, and revoke

Add the token-endpoint calls. They take an injectable async `post_form` callable so unit tests are network-free; the default uses `httpx`.

**Files:**
- Modify: `broker/oauth.py`
- Modify: `requirements.txt` (add `httpx>=0.27`), `pyproject.toml` (add `httpx>=0.27` to dependencies)
- Test: `tests/test_oauth_tokens.py`

**Interfaces:**
- Consumes: `OAuthError`.
- Produces (all `async`, all accept `post_form: PostForm | None = None`):
  - `PostForm = Callable[[str, dict], Awaitable[dict]]` (returns parsed JSON)
  - `exchange_code(*, token_url, client_id, client_secret, code, redirect_uri, verifier, post_form=None) -> dict` → `{"refresh_token": str, "access_token": str, "expires_at": str, "scopes": list[str]}`
  - `refresh_access_token(*, token_url, client_id, client_secret, refresh_token, post_form=None) -> dict` → `{"access_token": str, "expires_at": str, "scopes": list[str]}`
  - `revoke(*, revoke_url, token, post_form=None) -> None`

- [ ] **Step 1: Write the failing test**

Create `tests/test_oauth_tokens.py`:

```python
from __future__ import annotations

import datetime

import pytest

from broker import oauth


def _fake_post(response: dict):
    calls = []

    async def post_form(url: str, data: dict) -> dict:
        calls.append((url, data))
        return response

    post_form.calls = calls
    return post_form


async def test_exchange_code_parses_tokens():
    post = _fake_post({
        "access_token": "at-1", "refresh_token": "rt-1",
        "expires_in": 3600, "scope": "openid email",
    })
    result = await oauth.exchange_code(
        token_url="https://t", client_id="c", client_secret="s",
        code="authcode", redirect_uri="http://localhost:8765/callback",
        verifier="ver", post_form=post,
    )
    assert result["access_token"] == "at-1"
    assert result["refresh_token"] == "rt-1"
    assert result["scopes"] == ["openid", "email"]
    # expires_at is a future ISO timestamp
    assert datetime.datetime.fromisoformat(result["expires_at"]) > datetime.datetime.now()
    # grant_type and PKCE verifier were sent
    _, sent = post.calls[0]
    assert sent["grant_type"] == "authorization_code"
    assert sent["code_verifier"] == "ver"


async def test_exchange_code_error_response_raises():
    post = _fake_post({"error": "invalid_grant"})
    with pytest.raises(oauth.OAuthError):
        await oauth.exchange_code(
            token_url="https://t", client_id="c", client_secret="s",
            code="bad", redirect_uri="http://localhost:8765/callback",
            verifier="ver", post_form=post,
        )


async def test_refresh_access_token_parses():
    post = _fake_post({"access_token": "at-2", "expires_in": 1800, "scope": "read:user"})
    result = await oauth.refresh_access_token(
        token_url="https://t", client_id="c", client_secret="s",
        refresh_token="rt-1", post_form=post,
    )
    assert result["access_token"] == "at-2"
    assert result["scopes"] == ["read:user"]
    _, sent = post.calls[0]
    assert sent["grant_type"] == "refresh_token"
    assert sent["refresh_token"] == "rt-1"


async def test_revoke_calls_endpoint():
    post = _fake_post({})
    await oauth.revoke(revoke_url="https://r", token="rt-1", post_form=post)
    assert post.calls[0][0] == "https://r"
    assert post.calls[0][1]["token"] == "rt-1"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_oauth_tokens.py -v`
Expected: FAIL with `AttributeError: module 'broker.oauth' has no attribute 'exchange_code'`

- [ ] **Step 3: Write the implementation**

Add to the top imports of `broker/oauth.py`:

```python
import datetime
from collections.abc import Awaitable, Callable
```

Append to `broker/oauth.py`:

```python
PostForm = Callable[[str, dict], Awaitable[dict]]


async def _default_post_form(url: str, data: dict) -> dict:
    import httpx

    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=data, headers={"Accept": "application/json"})
    resp.raise_for_status()
    return resp.json()


def _expires_at(payload: dict) -> str:
    seconds = int(payload.get("expires_in", 3600))
    return (datetime.datetime.now() + datetime.timedelta(seconds=seconds)).isoformat(
        timespec="seconds"
    )


def _scopes(payload: dict) -> list[str]:
    scope = payload.get("scope", "")
    return scope.split() if scope else []


def _require_no_error(payload: dict) -> None:
    if "error" in payload:
        raise OAuthError(f"token endpoint error: {payload.get('error')}")


async def exchange_code(
    *,
    token_url: str,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
    verifier: str,
    post_form: PostForm | None = None,
) -> dict:
    post_form = post_form or _default_post_form
    payload = await post_form(
        token_url,
        {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
    )
    _require_no_error(payload)
    if "access_token" not in payload:
        raise OAuthError("token endpoint returned no access_token")
    return {
        "access_token": payload["access_token"],
        "refresh_token": payload.get("refresh_token", ""),
        "expires_at": _expires_at(payload),
        "scopes": _scopes(payload),
    }


async def refresh_access_token(
    *,
    token_url: str,
    client_id: str,
    client_secret: str,
    refresh_token: str,
    post_form: PostForm | None = None,
) -> dict:
    post_form = post_form or _default_post_form
    payload = await post_form(
        token_url,
        {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
        },
    )
    _require_no_error(payload)
    if "access_token" not in payload:
        raise OAuthError("token endpoint returned no access_token on refresh")
    return {
        "access_token": payload["access_token"],
        "expires_at": _expires_at(payload),
        "scopes": _scopes(payload),
    }


async def revoke(*, revoke_url: str, token: str, post_form: PostForm | None = None) -> None:
    post_form = post_form or _default_post_form
    await post_form(revoke_url, {"token": token})
```

Add `httpx>=0.27` to `requirements.txt` and to the `dependencies` list in `pyproject.toml`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_oauth_tokens.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add broker/oauth.py tests/test_oauth_tokens.py requirements.txt pyproject.toml
git commit -m "feat: oauth token exchange, refresh, and revoke"
```

---

### Task 6: Localhost callback server

A blocking helper that serves exactly the OAuth redirect, validates `state`, and returns the authorization `code`.

**Files:**
- Modify: `broker/oauth.py`
- Test: `tests/test_oauth_callback.py`

**Interfaces:**
- Consumes: `OAuthError`.
- Produces: `run_callback_server(*, port: int, expected_state: str, timeout: float = 300.0) -> str` — blocks until the provider redirects to `/callback`, validates that the returned `state` equals `expected_state`, and returns the `code`. Raises `OAuthError` on state mismatch, a returned `error`, or timeout.

- [ ] **Step 1: Write the failing test**

Create `tests/test_oauth_callback.py`:

```python
from __future__ import annotations

import threading
import time
import urllib.request

import pytest

from broker import oauth


def _hit(port: int, query: str):
    # Retry briefly until the server thread has bound the port.
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://localhost:{port}/callback?{query}", timeout=2)
            return
        except Exception:
            time.sleep(0.05)


def test_callback_returns_code():
    port = 8791
    result = {}

    def run():
        result["code"] = oauth.run_callback_server(
            port=port, expected_state="st8", timeout=10
        )

    t = threading.Thread(target=run)
    t.start()
    _hit(port, "code=authcode123&state=st8")
    t.join(timeout=10)
    assert result["code"] == "authcode123"


def test_callback_rejects_bad_state():
    port = 8792
    error = {}

    def run():
        try:
            oauth.run_callback_server(port=port, expected_state="GOOD", timeout=10)
        except oauth.OAuthError as exc:
            error["msg"] = str(exc)

    t = threading.Thread(target=run)
    t.start()
    _hit(port, "code=x&state=EVIL")
    t.join(timeout=10)
    assert "state" in error["msg"].lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_oauth_callback.py -v`
Expected: FAIL with `AttributeError: module 'broker.oauth' has no attribute 'run_callback_server'`

- [ ] **Step 3: Write the implementation**

Add to `broker/oauth.py` imports:

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
```

Append to `broker/oauth.py`:

```python
def run_callback_server(*, port: int, expected_state: str, timeout: float = 300.0) -> str:
    captured: dict = {}

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            query = parse_qs(urlparse(self.path).query)
            captured["error"] = (query.get("error") or [None])[0]
            captured["state"] = (query.get("state") or [None])[0]
            captured["code"] = (query.get("code") or [None])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"AgentGate: you may close this tab and return to the terminal.")

        def log_message(self, *args) -> None:  # silence default logging
            pass

    server = HTTPServer(("localhost", port), _Handler)
    server.timeout = timeout
    try:
        server.handle_request()  # serves exactly one request (or times out)
    finally:
        server.server_close()

    if not captured:
        raise OAuthError("timed out waiting for the OAuth redirect")
    if captured.get("error"):
        raise OAuthError(f"authorization failed: {captured['error']}")
    if captured.get("state") != expected_state:
        raise OAuthError("state mismatch on OAuth callback (possible CSRF)")
    if not captured.get("code"):
        raise OAuthError("OAuth callback returned no authorization code")
    return captured["code"]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_oauth_callback.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add broker/oauth.py tests/test_oauth_callback.py
git commit -m "feat: localhost OAuth callback server with state validation"
```

---

### Task 7: Token broker core (`request_token`)

Add the agent-facing token path to `Broker`, reusing the mode/policy/escalation/audit pipeline. Add an optional `scopes` field to audit entries (backward-compatible). Cache minted access tokens in memory until ~60s before expiry.

**Files:**
- Modify: `broker/mcp_server.py`
- Modify: `broker/audit.py` (add optional `scopes` param)
- Test: `tests/test_token_broker.py`, `tests/test_audit.py` (append one case)

**Interfaces:**
- Consumes: `ConnectionStore.get`, `oauth.get_preset`, `oauth.refresh_access_token`, `state.read_mode`, `ApprovalQueue.submit`, `AuditLogger.log`.
- Produces:
  - `AuditLogger.log(..., scopes: list[str] | None = None)` — entry includes `"scopes"` only when not `None`.
  - `Broker.__init__(..., connections: ConnectionStore | None = None)` (new optional kwarg; backward-compatible).
  - `Broker.request_token(self, agent: str, connection: str) -> dict` → `{"granted": bool, "access_token": str | None, "token_expiry": str | None, "scopes": list[str] | None, "reason": str}`.

- [ ] **Step 1: Write the failing audit test**

Append to `tests/test_audit.py`:

```python
def test_audit_includes_scopes_when_provided(tmp_path):
    import json
    from broker.audit import AuditLogger

    path = tmp_path / "audit.log"
    logger = AuditLogger(str(path))
    logger.log(
        agent="claude-code", credential_requested="work", policy_matched="p",
        decision="approved", mode="auto", token_expiry="2026-06-27T11:00:00",
        scopes=["openid", "email"],
    )
    entry = json.loads(path.read_text(encoding="utf-8").strip())
    assert entry["scopes"] == ["openid", "email"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_audit.py -k scopes -v`
Expected: FAIL with `TypeError: log() got an unexpected keyword argument 'scopes'`

- [ ] **Step 3: Add the `scopes` param to `AuditLogger.log`**

In `broker/audit.py`, change the `log` signature to add `scopes: list[str] | None = None` as the last keyword parameter, and after building `entry` (before the file write) add:

```python
        if scopes is not None:
            entry["scopes"] = scopes
```

- [ ] **Step 4: Run audit test to verify it passes**

Run: `python -m pytest tests/test_audit.py -v`
Expected: PASS (existing audit tests unchanged + new scopes test)

- [ ] **Step 5: Write the failing token-broker test**

Create `tests/test_token_broker.py`:

```python
from __future__ import annotations

import json
import textwrap

import pytest

from broker import oauth
from broker.approval import ApprovalQueue
from broker.audit import AuditLogger
from broker.config import Config
from broker.connection_store import Connection, ConnectionStore
from broker.mcp_server import Broker
from broker.policy_engine import PolicyEngine


def _make_broker(tmp_path, policy_body, monkeypatch):
    pol = tmp_path / "policies.yaml"
    pol.write_text(textwrap.dedent(policy_body))
    env = {
        "POLICIES_PATH": str(pol),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "CONNECTIONS_PATH": str(tmp_path / "connections.json"),
        "AGENTGATE_MASTER_PASSWORD": "pw",
    }
    cfg = Config.from_env(env)
    connections = ConnectionStore(cfg.connections_path, "pw")
    connections.store("work", Connection(
        provider="google", client_id="cid", client_secret="csec",
        refresh_token="rt", scopes=["openid", "email"], created_at="2026-06-27T10:00:00",
    ))
    # Stub the network refresh so no real HTTP happens.
    async def fake_refresh(**kwargs):
        return {"access_token": "AT-fresh", "expires_at": "2099-01-01T00:00:00",
                "scopes": ["openid", "email"]}
    monkeypatch.setattr(oauth, "refresh_access_token", fake_refresh)

    from broker.credential_store import CredentialStore
    broker = Broker(
        config=cfg,
        store=CredentialStore(cfg.credentials_path, "pw"),
        engine=PolicyEngine.from_file(cfg.policies_path),
        audit=AuditLogger(cfg.logs_path),
        approvals=ApprovalQueue(),
        connections=connections,
    )
    return broker, tmp_path


_AUTO = """
    policies:
      - name: cc-work
        agent: claude-code
        credential: work
        auto_approve: true
      - name: default-deny
        agent: "*"
        credential: "*"
        auto_approve: false
        escalate: true
"""


async def test_auto_approve_mints_token(tmp_path, monkeypatch):
    broker, _ = _make_broker(tmp_path, _AUTO, monkeypatch)
    res = await broker.request_token("claude-code", "work")
    assert res["granted"] is True
    assert res["access_token"] == "AT-fresh"
    assert res["scopes"] == ["openid", "email"]


async def test_unknown_connection_denied(tmp_path, monkeypatch):
    import asyncio
    broker, _ = _make_broker(tmp_path, _AUTO, monkeypatch)
    # 'nonexistent' hits default-deny -> escalate; resolve as approved,
    # then the missing connection makes the grant fail closed.
    task = asyncio.ensure_future(broker.request_token("claude-code", "nonexistent"))
    await asyncio.sleep(0.05)
    p = broker.approvals.get_pending()
    broker.approvals.resolve(p, True)
    res = await task
    assert res["granted"] is False
    assert "nonexistent" in res["reason"]


async def test_audit_never_contains_secrets(tmp_path, monkeypatch):
    broker, tp = _make_broker(tmp_path, _AUTO, monkeypatch)
    await broker.request_token("claude-code", "work")
    log = (tp / "audit.log").read_text(encoding="utf-8")
    assert "AT-fresh" not in log   # access token value never logged
    assert "csec" not in log       # client secret never logged
    entry = json.loads(log.strip().splitlines()[-1])
    assert entry["decision"] == "approved"
    assert entry["scopes"] == ["openid", "email"]
```

- [ ] **Step 6: Run token-broker test to verify it fails**

Run: `python -m pytest tests/test_token_broker.py -v`
Expected: FAIL with `TypeError: __init__() got an unexpected keyword argument 'connections'`

- [ ] **Step 7: Implement `request_token` and the `connections` kwarg**

In `broker/mcp_server.py`, add `from broker import oauth` and `from broker.connection_store import ConnectionStore` to the imports.

Add `connections: ConnectionStore | None = None` as a new keyword parameter to `Broker.__init__`, and in the body set:

```python
        self.connections = connections
        self._token_cache: dict[str, dict] = {}
```

Add these methods to `Broker`:

```python
    async def request_token(self, agent: str, connection: str) -> dict:
        self.total_requests += 1
        mode = state.read_mode(self.config.state_path)

        if mode == "manual":
            return await self._escalate_token(agent, connection, mode, "manual-mode")

        decision = self.engine.evaluate(agent, connection)
        if decision.auto_approve:
            return await self._grant_token(agent, connection, mode, decision.policy_name)
        return await self._escalate_token(agent, connection, mode, decision.policy_name)

    async def _grant_token(self, agent: str, connection: str, mode: str, policy_name: str) -> dict:
        try:
            conn = self.connections.get(connection)
        except (AttributeError, KeyError):
            self.audit.log(
                agent=agent, credential_requested=connection, policy_matched=policy_name,
                decision="denied", mode=mode, token_expiry=None,
            )
            return {"granted": False, "access_token": None, "token_expiry": None,
                    "scopes": None, "reason": f"unknown connection '{connection}'"}

        token = self._cached_token(connection)
        if token is None:
            preset = oauth.get_preset(conn.provider)
            fresh = await oauth.refresh_access_token(
                token_url=preset.token_url, client_id=conn.client_id,
                client_secret=conn.client_secret, refresh_token=conn.refresh_token,
            )
            token = {"access_token": fresh["access_token"], "expires_at": fresh["expires_at"],
                     "scopes": fresh["scopes"] or conn.scopes}
            self._token_cache[connection] = token

        self.audit.log(
            agent=agent, credential_requested=connection, policy_matched=policy_name,
            decision="approved", mode=mode, token_expiry=token["expires_at"],
            scopes=token["scopes"],
        )
        return {"granted": True, "access_token": token["access_token"],
                "token_expiry": token["expires_at"], "scopes": token["scopes"],
                "reason": f"auto-approved by policy '{policy_name}'"}

    def _cached_token(self, connection: str) -> dict | None:
        token = self._token_cache.get(connection)
        if token is None:
            return None
        try:
            expires = datetime.datetime.fromisoformat(token["expires_at"])
        except ValueError:
            return None
        if datetime.datetime.now() >= expires - datetime.timedelta(seconds=60):
            self._token_cache.pop(connection, None)
            return None
        return token

    async def _escalate_token(self, agent: str, connection: str, mode: str, policy_name: str) -> dict:
        self.escalated_requests += 1
        self.audit.log(
            agent=agent, credential_requested=connection, policy_matched=policy_name,
            decision="escalated", mode=mode, token_expiry=None,
        )
        try:
            approved = await self.approvals.submit(
                agent, connection, timeout=self.config.escalation_timeout_seconds or None
            )
        except asyncio.TimeoutError:
            self.audit.log(
                agent=agent, credential_requested=connection, policy_matched=policy_name,
                decision="expired", mode=mode, token_expiry=None,
            )
            return {"granted": False, "access_token": None, "token_expiry": None,
                    "scopes": None, "reason": "escalation timed out"}
        if approved:
            return await self._grant_token(agent, connection, mode, f"manual:{policy_name}")
        self.audit.log(
            agent=agent, credential_requested=connection, policy_matched=policy_name,
            decision="denied", mode=mode, token_expiry=None,
        )
        return {"granted": False, "access_token": None, "token_expiry": None,
                "scopes": None, "reason": "denied by operator"}
```

- [ ] **Step 8: Run the token-broker test to verify it passes**

Run: `python -m pytest tests/test_token_broker.py tests/test_audit.py -v`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add broker/mcp_server.py broker/audit.py tests/test_token_broker.py tests/test_audit.py
git commit -m "feat: request_token broker path with token cache and scoped audit"
```

---

### Task 8: `token.request` MCP tool + broker wiring

Expose `request_token` as an MCP tool and wire `build_broker` to construct a `ConnectionStore`.

**Files:**
- Modify: `broker/mcp_server.py` (add tool in `build_mcp`)
- Modify: `broker/main.py` (`build_broker` constructs `ConnectionStore`)
- Test: `tests/test_token_tool.py`

**Interfaces:**
- Consumes: `Broker.request_token`, `build_mcp`, `fastmcp.Client`.
- Produces: MCP tool `token.request({agent, connection}) -> dict`; `build_broker` now passes `connections=ConnectionStore(config.connections_path, master_password)`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_token_tool.py`:

```python
from __future__ import annotations

import textwrap

import pytest
from fastmcp import Client

from broker import oauth
from broker.approval import ApprovalQueue
from broker.audit import AuditLogger
from broker.config import Config
from broker.connection_store import Connection, ConnectionStore
from broker.credential_store import CredentialStore
from broker.mcp_server import Broker, build_mcp
from broker.policy_engine import PolicyEngine


async def test_token_request_tool_registered_and_grants(tmp_path, monkeypatch):
    pol = tmp_path / "policies.yaml"
    pol.write_text(textwrap.dedent("""
        policies:
          - name: cc-work
            agent: claude-code
            credential: work
            auto_approve: true
    """))
    env = {
        "POLICIES_PATH": str(pol), "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "CONNECTIONS_PATH": str(tmp_path / "connections.json"),
        "AGENTGATE_MASTER_PASSWORD": "pw",
    }
    cfg = Config.from_env(env)
    connections = ConnectionStore(cfg.connections_path, "pw")
    connections.store("work", Connection(
        provider="google", client_id="cid", client_secret="csec",
        refresh_token="rt", scopes=["openid"], created_at="2026-06-27T10:00:00"))

    async def fake_refresh(**kwargs):
        return {"access_token": "AT-tool", "expires_at": "2099-01-01T00:00:00", "scopes": ["openid"]}
    monkeypatch.setattr(oauth, "refresh_access_token", fake_refresh)

    broker = Broker(
        config=cfg, store=CredentialStore(cfg.credentials_path, "pw"),
        engine=PolicyEngine.from_file(cfg.policies_path),
        audit=AuditLogger(cfg.logs_path), approvals=ApprovalQueue(),
        connections=connections,
    )
    mcp = build_mcp(broker)
    async with Client(mcp) as client:
        tools = [t.name for t in await client.list_tools()]
        assert "token.request" in tools
        res = await client.call_tool("token.request", {"agent": "claude-code", "connection": "work"})
        assert res.data["granted"] is True
        assert res.data["access_token"] == "AT-tool"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_token_tool.py -v`
Expected: FAIL (`token.request` not in registered tools / KeyError)

- [ ] **Step 3: Add the MCP tool**

In `broker/mcp_server.py`, inside `build_mcp`, add before `return mcp`:

```python
    @mcp.tool(name="token.request")
    async def token_request(agent: str, connection: str) -> dict:
        return await broker.request_token(agent, connection)
```

- [ ] **Step 4: Wire `build_broker`**

In `broker/main.py`, import `from broker.connection_store import ConnectionStore`, and in `build_broker` construct the store and pass it:

```python
    return Broker(
        config=config,
        store=store,
        engine=PolicyEngine.from_file(config.policies_path),
        audit=AuditLogger(config.logs_path),
        approvals=ApprovalQueue(),
        connections=ConnectionStore(config.connections_path, master_password),
    )
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/test_token_tool.py tests/test_main.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add broker/mcp_server.py broker/main.py tests/test_token_tool.py
git commit -m "feat: token.request MCP tool wired into broker"
```

---

### Task 9: Operator CLI — `connect`, `connections`, `disconnect`

Add the three operator commands. `connect` runs the interactive flow; `connections` lists metadata; `disconnect` revokes at the provider and deletes the record.

**Files:**
- Modify: `cli/commands.py`
- Test: `tests/test_cli_oauth.py`

**Interfaces:**
- Consumes: `ConnectionStore`, `oauth` (presets, PKCE, `build_auth_url`, `run_callback_server`, `exchange_code`, `revoke`), `Config`.
- Produces: CLI subcommands `connect <provider> [name]`, `connections`, `disconnect <name>`. Client ID/secret read from env `AGENTGATE_OAUTH_CLIENT_ID` / `AGENTGATE_OAUTH_CLIENT_SECRET` at `connect` time. A seam function `_run_connect(config, master_password, provider, name, *, open_browser, wait_for_code)` is used so tests can inject the browser-open and callback behavior.

- [ ] **Step 1: Write the failing test**

Create `tests/test_cli_oauth.py`:

```python
from __future__ import annotations

import asyncio

import pytest

from broker import oauth
from broker.config import Config
from broker.connection_store import Connection, ConnectionStore
from cli import commands


def _cfg(tmp_path):
    env = {
        "POLICIES_PATH": str(tmp_path / "policies.yaml"),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "CONNECTIONS_PATH": str(tmp_path / "connections.json"),
    }
    return Config.from_env(env)


def test_connections_lists_without_secrets(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    ConnectionStore(cfg.connections_path, "pw").store("work", Connection(
        provider="google", client_id="cid", client_secret="csec", refresh_token="rt",
        scopes=["openid"], created_at="2026-06-27T10:00:00"))
    rc = commands.run(["connections"], config=cfg, master_password="pw")
    out = capsys.readouterr().out
    assert rc == 0
    assert "work" in out and "google" in out
    assert "csec" not in out and "rt" not in out


def test_disconnect_revokes_and_deletes(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    store = ConnectionStore(cfg.connections_path, "pw")
    store.store("work", Connection(
        provider="google", client_id="cid", client_secret="csec", refresh_token="rt",
        scopes=["openid"], created_at="2026-06-27T10:00:00"))
    revoked = {}

    async def fake_revoke(**kwargs):
        revoked["token"] = kwargs["token"]
    monkeypatch.setattr(oauth, "revoke", fake_revoke)

    rc = commands.run(["disconnect", "work"], config=cfg, master_password="pw")
    assert rc == 0
    assert revoked["token"] == "rt"
    assert ConnectionStore(cfg.connections_path, "pw").list_names() == []


def test_connect_stores_connection(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    monkeypatch.setenv("AGENTGATE_OAUTH_CLIENT_ID", "cid")
    monkeypatch.setenv("AGENTGATE_OAUTH_CLIENT_SECRET", "csec")
    monkeypatch.setattr(commands.webbrowser, "open", lambda url: True)
    monkeypatch.setattr(oauth, "run_callback_server", lambda **kw: "authcode")

    async def fake_exchange(**kwargs):
        return {"access_token": "AT", "refresh_token": "RT-new",
                "expires_at": "2099-01-01T00:00:00", "scopes": ["openid", "email"]}
    monkeypatch.setattr(oauth, "exchange_code", fake_exchange)

    rc = commands.run(["connect", "google", "work"], config=cfg, master_password="pw")
    assert rc == 0
    conn = ConnectionStore(cfg.connections_path, "pw").get("work")
    assert conn.refresh_token == "RT-new"
    assert conn.provider == "google"
    assert conn.scopes == ["openid", "email"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli_oauth.py -v`
Expected: FAIL (`connect`/`connections`/`disconnect` not recognized; `commands.webbrowser` missing)

- [ ] **Step 3: Implement the commands**

In `cli/commands.py`, add imports at the top:

```python
import asyncio
import datetime
import secrets
import webbrowser

from broker import oauth
from broker.connection_store import Connection, ConnectionStore
```

In `build_parser`, register the subcommands (after the existing `status` parser):

```python
    c = sub.add_parser("connect", help="connect an OAuth provider account")
    c.add_argument("provider")
    c.add_argument("name", nargs="?", default=None)
    sub.add_parser("connections", help="list connected accounts")
    dc = sub.add_parser("disconnect", help="revoke and remove a connection")
    dc.add_argument("name")
```

Add the command handlers in `run` (after the `status` block, before `return 2`):

```python
    if args.command == "connections":
        store = ConnectionStore(config.connections_path, _password(master_password))
        for meta in store.list_metadata():
            print(f"{meta['name']}  provider={meta['provider']}  "
                  f"scopes={','.join(meta['scopes'])}  created={meta['created_at']}")
        return 0

    if args.command == "disconnect":
        store = ConnectionStore(config.connections_path, _password(master_password))
        try:
            conn = store.get(args.name)
        except KeyError:
            print(f"no such connection '{args.name}'", file=sys.stderr)
            return 1
        preset = oauth.get_preset(conn.provider)
        if preset.revoke_url:
            asyncio.run(oauth.revoke(revoke_url=preset.revoke_url, token=conn.refresh_token))
        store.delete(args.name)
        print(f"disconnected '{args.name}'")
        return 0

    if args.command == "connect":
        return _run_connect(config, _password(master_password), args.provider, args.name)
```

Add the helper functions at module level:

```python
def _run_connect(config: Config, master_password: str, provider: str, name: str | None) -> int:
    name = name or provider
    client_id = os.environ.get("AGENTGATE_OAUTH_CLIENT_ID")
    client_secret = os.environ.get("AGENTGATE_OAUTH_CLIENT_SECRET")
    if not client_id or not client_secret:
        print("set AGENTGATE_OAUTH_CLIENT_ID and AGENTGATE_OAUTH_CLIENT_SECRET "
              "for the provider you are connecting", file=sys.stderr)
        return 2
    try:
        preset = oauth.get_preset(provider)
    except oauth.OAuthError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    redirect_uri = f"http://localhost:{config.oauth_redirect_port}/callback"
    verifier, challenge = oauth.generate_pkce()
    state = secrets.token_urlsafe(16)
    url = oauth.build_auth_url(
        preset=preset, client_id=client_id, redirect_uri=redirect_uri,
        scopes=preset.default_scopes, state=state, challenge=challenge,
    )
    print(f"Opening browser to authorize {provider}. Approve access, then return here.")
    webbrowser.open(url)
    code = oauth.run_callback_server(port=config.oauth_redirect_port, expected_state=state)
    tokens = asyncio.run(oauth.exchange_code(
        token_url=preset.token_url, client_id=client_id, client_secret=client_secret,
        code=code, redirect_uri=redirect_uri, verifier=verifier,
    ))
    if not tokens["refresh_token"]:
        print("provider returned no refresh token; re-consent with offline access",
              file=sys.stderr)
        return 1
    ConnectionStore(config.connections_path, master_password).store(name, Connection(
        provider=provider, client_id=client_id, client_secret=client_secret,
        refresh_token=tokens["refresh_token"],
        scopes=tokens["scopes"] or preset.default_scopes,
        created_at=datetime.datetime.now().isoformat(timespec="seconds"),
    ))
    print(f"connected '{name}' ({provider})")
    return 0
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_cli_oauth.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Run the whole suite**

Run: `python -m pytest -q`
Expected: PASS (all V1 + V2 tests green)

- [ ] **Step 6: Commit**

```bash
git add cli/commands.py tests/test_cli_oauth.py
git commit -m "feat: connect/connections/disconnect operator commands"
```

---

### Task 10: Documentation

Document the OAuth broker: README section, env-var reference, and `.env.example` entries. No code; keep claims accurate to what was built.

**Files:**
- Modify: `README.md`
- Modify: `.env.example` (if present; else create) — add `CONNECTIONS_PATH`, `OAUTH_REDIRECT_PORT`, and note `AGENTGATE_OAUTH_CLIENT_ID` / `AGENTGATE_OAUTH_CLIENT_SECRET` used at connect time

- [ ] **Step 1: Add a README "OAuth broker" section**

Document, accurately matching the implementation:
- The mental model (connect once → agents request a connection by name → short-lived scoped token; refresh token never leaves the broker).
- One-time provider setup: register an OAuth app, set the redirect URI to `http://localhost:8765/callback` (or the configured `OAUTH_REDIRECT_PORT`), obtain client ID/secret.
- Commands: `agentgate connect google work`, `agentgate connections`, `agentgate disconnect work`. Note `AGENTGATE_OAUTH_CLIENT_ID` / `AGENTGATE_OAUTH_CLIENT_SECRET` must be set in the environment when running `connect`.
- The agent-facing MCP tool `token.request({agent, connection})` and that policy/escalation/audit govern it exactly like `credential.request`.
- Security note: only access tokens are released to agents; refresh tokens and client secrets are encrypted at rest and never logged.

- [ ] **Step 2: Update `.env.example`**

Add the new variables with comments:

```bash
# OAuth broker
CONNECTIONS_PATH=data/connections.json
OAUTH_REDIRECT_PORT=8765
# Set these only when running `agentgate connect <provider>`:
# AGENTGATE_OAUTH_CLIENT_ID=...
# AGENTGATE_OAUTH_CLIENT_SECRET=...
```

- [ ] **Step 3: Verify docs match reality**

Run: `python -m pytest -q`
Expected: PASS (sanity check that nothing referenced in docs drifted)

- [ ] **Step 4: Commit**

```bash
git add README.md .env.example
git commit -m "docs: OAuth broker usage and env-var reference"
```

---

## Self-Review

**1. Spec coverage**

- Interactive onboarding (auth-code + PKCE, fixed localhost callback) → Tasks 4, 6, 9.
- Google + GitHub presets + generic path → Task 4 (`PRESETS`, `get_preset`); generic via supplying client ID/secret + a preset is the V2 cut (generic-URL config deferred — see note).
- Encrypted connections store → Tasks 1, 2.
- `token.request` MCP tool reusing policy/escalation/audit → Tasks 7, 8.
- AUTO/MANUAL + escalation + fail-closed timeout → Task 7 (`_escalate_token`).
- Revocation on disconnect → Task 9.
- Security properties (no password stored; refresh token/client secret never returned or logged; only access tokens released) → Tasks 2, 7 (audit excludes secrets; tests assert it).
- Config paths/ports via env → Task 3.

**Gap noted:** The spec mentions a "generic OAuth2 config path for any other provider." This plan ships the Google + GitHub presets and the full flow, but a generic provider would currently require adding an entry to `PRESETS`. A user-facing generic path (custom auth/token URLs via env/config) is **deferred to a follow-up** to keep this plan's surface focused; the preset table is the extension point. This is consistent with the spec's "presets for Google + GitHub (chosen option), generic as fallback" — the fallback is a small future addition, not core to first delivery.

**2. Placeholder scan:** No TBD/TODO; every code step contains complete code; every test step contains real assertions.

**3. Type consistency:** `Connection` fields, `ConnectionStore` method names, `oauth.*` signatures, `Broker.request_token` return keys (`granted`/`access_token`/`token_expiry`/`scopes`/`reason`), and the `post_form`/`refresh_access_token` keyword arguments are used identically across Tasks 2, 4, 5, 7, 8, 9. Audit `scopes` param added once (Task 7) and used by `request_token`.
