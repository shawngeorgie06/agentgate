# AgentGate AWS Broker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Agents get short-lived, IAM-scoped AWS credentials via STS AssumeRole — never a standing access key.

**Architecture:** The operator stores one dedicated IAM user's access key encrypted (`sts:AssumeRole`-only) and registers resources as role ARNs. On `aws_credential_request` the broker (after auth → policy → escalation) assumes the resource's role with `RoleSessionName=agentgate-<agent>-<resource>` and `DurationSeconds=TTL×60`, returning the temporary keypair + session token. STS credentials expire natively — no reaper. Auth/policy/escalation/audit spine reused unchanged.

**Tech Stack:** Python 3.11+, `boto3` (lazy-imported behind an injectable `StsExecutor`; unit tests use a fake and NEVER import boto3), fastmcp, pytest (`asyncio_mode = auto`: async tests need no decorator).

## Global Constraints

- The issued `secret_access_key`/`session_token` appear ONLY in the tool response — never in audit records, logs, error messages, `reason` strings, or dataclass `repr` (use `field(repr=False)`).
- The broker's own IAM secret key is encrypted at rest (Argon2id + AES-256-GCM via `EncryptedStore`/`crypto`), never printed, never in argv.
- boto3 exception text (which can embed ARNs, request IDs, endpoints) NEVER reaches a `reason` or the audit. All STS/validation/store failures return a GENERIC reason.
- Every denial path writes an audited `decision="denied"` (or `"expired"`) row AND returns the full null-field response shape `{granted: false, access_key_id: null, secret_access_key: null, session_token: null, expiration: null, region: null, reason}`.
- Authentication strictly precedes escalation — an unknown agent must never create a pending approval, even in MANUAL mode.
- Validate at input AND at the STS sink: role ARN, region, external ID validated at `aws-add`; role ARN, region, external ID, and session name re-validated inside `aws_broker.assume_role` before the STS call. Canonical patterns live ONLY in `broker/aws_validation.py` (leaf module — the `role_naming.py`/`ssh_validation.py` discipline). Always `.fullmatch`, never `.match`.
- `Boto3StsExecutor` constructs its client with explicit key arguments ONLY — it must never fall back to the ambient credential chain (env/`~/.aws`/instance profile).
- Session name is `agentgate-<agent>-<resource>`, truncated to 64 chars, sink-validated against `[\w+=,.@-]{2,64}`; if it fails after truncation the request denies generically.
- `AWS_CRED_TTL_MINUTES` default 15, integer ≥ 15 (the STS 900-second floor).
- MCP tool name is exactly `aws_credential_request` (underscores). Tool count becomes 9; grant-or-change count becomes 6.
- `boto3>=1.34` added to `requirements.txt` and `pyproject.toml`. Commit messages follow the existing `feat:`/`fix:`/`docs:` convention; all commits end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

---

### Task 1: `broker/aws_validation.py` — leaf validation module

**Files:**
- Create: `broker/aws_validation.py`
- Test: `tests/test_aws_validation.py`

**Interfaces:**
- Consumes: nothing (leaf module; imports only `re`).
- Produces: `AwsValidationError(ValueError)`; compiled `ROLE_ARN_RE`, `SESSION_NAME_RE`, `EXTERNAL_ID_RE`, `REGION_RE` (all unanchored — used with `.fullmatch`); `validate_role_arn(raw) -> str`, `validate_region(raw) -> str`, `validate_external_id(raw) -> str`, `validate_session_name(raw) -> str`. Tasks 4 and 6 import these.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_aws_validation.py
from __future__ import annotations

import pytest

from broker.aws_validation import (
    AwsValidationError,
    ROLE_ARN_RE,
    validate_external_id,
    validate_region,
    validate_role_arn,
    validate_session_name,
)


def test_valid_role_arns_pass():
    arn = "arn:aws:iam::123456789012:role/agent-s3-reader"
    assert validate_role_arn(arn) == arn
    assert validate_role_arn("arn:aws:iam::000000000000:role/team/path/Role_1") == \
        "arn:aws:iam::000000000000:role/team/path/Role_1"


@pytest.mark.parametrize("bad", [
    "", "arn:aws:iam::123:role/x",              # account id not 12 digits
    "arn:aws:iam::123456789012:user/x",         # not a role
    "arn:aws:s3:::bucket",                       # wrong service
    "arn:aws:iam::123456789012:role/x\n",       # trailing newline
    "arn:aws:iam::12345678901a:role/x",          # non-digit account
    42, None,
])
def test_invalid_role_arns_raise(bad):
    with pytest.raises(AwsValidationError):
        validate_role_arn(bad)


def test_role_arn_re_is_fullmatch_safe_against_trailing_newline():
    assert ROLE_ARN_RE.fullmatch("arn:aws:iam::123456789012:role/x")
    assert not ROLE_ARN_RE.fullmatch("arn:aws:iam::123456789012:role/x\n")


def test_valid_regions_pass():
    for r in ("us-east-1", "eu-west-2", "ap-southeast-1"):
        assert validate_region(r) == r


@pytest.mark.parametrize("bad", ["", "US-EAST-1", "useast1", "us-east", "us-east-1\n", 42, None])
def test_invalid_regions_raise(bad):
    with pytest.raises(AwsValidationError):
        validate_region(bad)


def test_valid_session_names_pass():
    assert validate_session_name("agentgate-claude-code-s3") == "agentgate-claude-code-s3"
    assert validate_session_name("a+b=c,d.e@f-2") == "a+b=c,d.e@f-2"


@pytest.mark.parametrize("bad", ["", "x", "a b", "name\n", "a" * 65, "bad/slash", 42, None])
def test_invalid_session_names_raise(bad):
    # STS RoleSessionName charset is [\w+=,.@-], length 2..64.
    with pytest.raises(AwsValidationError):
        validate_session_name(bad)


def test_valid_external_ids_pass():
    assert validate_external_id("my-external-id") == "my-external-id"
    assert validate_external_id("org:team/proj@1") == "org:team/proj@1"


@pytest.mark.parametrize("bad", ["", "x", "id with space", "id\n", 42, None])
def test_invalid_external_ids_raise(bad):
    with pytest.raises(AwsValidationError):
        validate_external_id(bad)


def test_error_is_a_valueerror():
    assert issubclass(AwsValidationError, ValueError)
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_aws_validation.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'broker.aws_validation'`.

- [ ] **Step 3: Implement**

```python
# broker/aws_validation.py
from __future__ import annotations

import re

# Canonical validation for values that reach the STS AssumeRole call.
#
# SINGLE SOURCE OF TRUTH for the ARN / region / session-name / external-id
# patterns, enforced both at operator input (`aws-add`) and again at the STS
# sink (broker/aws_broker.py) — the validate-at-input-AND-sink discipline
# shared with db_grants / ssh_validation. Leaf module (imports nothing from
# broker) so the two enforcement points cannot drift. ALWAYS use .fullmatch
# (patterns are deliberately unanchored; .match would admit a trailing
# newline).

# IAM role ARN: arn:aws:iam::<12-digit account>:role/<path+name>.
ROLE_ARN_RE = re.compile(r"arn:aws:iam::\d{12}:role/[\w+=,.@/-]+")
# STS RoleSessionName: 2..64 chars from [\w+=,.@-].
SESSION_NAME_RE = re.compile(r"[\w+=,.@-]{2,64}")
# STS ExternalId: 2..1224 chars from a documented safe set.
EXTERNAL_ID_RE = re.compile(r"[\w+=,.@:/-]{2,1224}")
# AWS region, e.g. us-east-1, ap-southeast-1.
REGION_RE = re.compile(r"[a-z]{2}(-[a-z]+)+-\d")


class AwsValidationError(ValueError):
    """Raised when a role ARN, region, session name, or external id is unsafe."""


def _check(raw: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(raw, str) or not pattern.fullmatch(raw):
        raise AwsValidationError(f"invalid {label} {raw!r}")
    return raw


def validate_role_arn(raw: object) -> str:
    return _check(raw, ROLE_ARN_RE, "role ARN")


def validate_region(raw: object) -> str:
    return _check(raw, REGION_RE, "region")


def validate_external_id(raw: object) -> str:
    return _check(raw, EXTERNAL_ID_RE, "external id")


def validate_session_name(raw: object) -> str:
    return _check(raw, SESSION_NAME_RE, "session name")
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_aws_validation.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add broker/aws_validation.py tests/test_aws_validation.py
git commit -m "feat: aws validation leaf module (role ARN / region / session-name / external-id)"
```

---

### Task 2: `broker/aws_executor.py` — STS executor seam

**Files:**
- Create: `broker/aws_executor.py`
- Test: `tests/test_aws_executor.py`

**Interfaces:**
- Consumes: nothing at import time (boto3 lazy-imported inside the method).
- Produces: `StsExecutor(Protocol)` with `async assume_role(access_key_id, secret_access_key, *, role_arn, session_name, duration_seconds, region, external_id) -> dict` returning `{"access_key_id", "secret_access_key", "session_token", "expiration"}` (expiration a UTC ISO string); `Boto3StsExecutor` implementing it. Tasks 3, 4, 5 consume the protocol; Task 5 wires the concrete class.

- [ ] **Step 1: Write the failing test**

The real executor needs AWS, so the only import-time-safe unit test asserts the protocol shape and that a hand-written fake satisfies it. (The concrete boto3 path is covered by the skip-gated integration test in Task 7.)

```python
# tests/test_aws_executor.py
from __future__ import annotations

import inspect

from broker.aws_executor import Boto3StsExecutor, StsExecutor


def test_protocol_method_signature():
    sig = inspect.signature(StsExecutor.assume_role)
    params = list(sig.parameters)
    assert params == [
        "self", "access_key_id", "secret_access_key", "role_arn",
        "session_name", "duration_seconds", "region", "external_id",
    ]


def test_boto3_executor_satisfies_protocol_without_importing_boto3():
    # Importing the module must NOT import boto3 (it is lazy). Constructing the
    # executor is also import-free; only calling assume_role would import boto3.
    import sys
    assert "boto3" not in sys.modules
    ex = Boto3StsExecutor()
    assert isinstance(ex, StsExecutor)


class _FakeSts:
    def __init__(self):
        self.calls = []

    async def assume_role(self, access_key_id, secret_access_key, *, role_arn,
                          session_name, duration_seconds, region, external_id):
        self.calls.append(dict(
            access_key_id=access_key_id, role_arn=role_arn, session_name=session_name,
            duration_seconds=duration_seconds, region=region, external_id=external_id,
        ))
        return {"access_key_id": "ASIA_FAKE", "secret_access_key": "s3cr3t",
                "session_token": "tok", "expiration": "2026-07-06T10:15:00+00:00"}


def test_fake_satisfies_protocol():
    assert isinstance(_FakeSts(), StsExecutor)
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_aws_executor.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'broker.aws_executor'`.

- [ ] **Step 3: Implement**

```python
# broker/aws_executor.py
from __future__ import annotations

import asyncio
import datetime
from typing import Protocol, runtime_checkable


@runtime_checkable
class StsExecutor(Protocol):
    async def assume_role(
        self,
        access_key_id: str,
        secret_access_key: str,
        *,
        role_arn: str,
        session_name: str,
        duration_seconds: int,
        region: str,
        external_id: str | None,
    ) -> dict:
        ...


class Boto3StsExecutor:
    """Real STS caller. boto3 is imported lazily inside assume_role so the
    broker runs (and the whole unit-test suite imports) without boto3 present;
    a missing boto3 surfaces as an exception the grant path turns into a
    generic audited deny. The client is built with EXPLICIT keys only — never
    the ambient credential chain."""

    async def assume_role(
        self,
        access_key_id: str,
        secret_access_key: str,
        *,
        role_arn: str,
        session_name: str,
        duration_seconds: int,
        region: str,
        external_id: str | None,
    ) -> dict:
        return await asyncio.to_thread(
            self._assume_role_sync,
            access_key_id, secret_access_key, role_arn, session_name,
            duration_seconds, region, external_id,
        )

    @staticmethod
    def _assume_role_sync(
        access_key_id, secret_access_key, role_arn, session_name,
        duration_seconds, region, external_id,
    ) -> dict:
        import boto3  # lazy: keeps import-time (and tests) boto3-free

        client = boto3.client(
            "sts",
            region_name=region,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
        )
        kwargs = dict(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            DurationSeconds=duration_seconds,
        )
        if external_id is not None:
            kwargs["ExternalId"] = external_id
        resp = client.assume_role(**kwargs)
        creds = resp["Credentials"]
        expiration = creds["Expiration"]
        if isinstance(expiration, datetime.datetime):
            expiration = expiration.astimezone(datetime.timezone.utc).isoformat(
                timespec="seconds"
            )
        return {
            "access_key_id": creds["AccessKeyId"],
            "secret_access_key": creds["SecretAccessKey"],
            "session_token": creds["SessionToken"],
            "expiration": expiration,
        }
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_aws_executor.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add broker/aws_executor.py tests/test_aws_executor.py
git commit -m "feat: STS executor seam (lazy boto3, explicit-keys-only, to_thread)"
```

---

### Task 3: `broker/aws_broker.py` — session-name build + assume_role orchestration

**Files:**
- Create: `broker/aws_broker.py`
- Test: `tests/test_aws_broker.py`

**Interfaces:**
- Consumes: `broker.aws_validation` (Task 1); `broker.aws_executor.StsExecutor` (Task 2); `broker.aws_resource_store.AwsResource` (Task 4 — a frozen dataclass with `name, role_arn, region, external_id, created_at`) and `broker.aws_key_store.AwsBrokerKey` (Task 4 — `access_key_id, secret_access_key`). NOTE: this task is implemented BEFORE Task 4, so it defines lightweight local test doubles for `AwsResource`/`AwsBrokerKey` shapes in its own test and imports the real ones only through the function signature (duck-typed attributes). Do NOT import from `aws_resource_store`/`aws_key_store` in `aws_broker.py`; accept any object exposing the needed attributes.
- Produces: `SESSION_PREFIX = "agentgate-"`; `build_session_name(agent: str, resource: str) -> str` (compose, truncate to 64, sink-validate → raises `AwsValidationError`); `AwsCred(access_key_id, secret_access_key, session_token, expiration, region)` (secret fields `field(repr=False)`); `async assume_role(executor, key, resource, ttl_minutes: int, session_name: str) -> AwsCred`. Task 5 consumes these.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_aws_broker.py
from __future__ import annotations

import pytest

from broker import aws_broker
from broker.aws_broker import AwsCred, build_session_name
from broker.aws_validation import AwsValidationError


class _Key:
    access_key_id = "AKIA_BROKER"
    secret_access_key = "broker-secret"


class _Res:
    def __init__(self, external_id=None):
        self.name = "s3-reader"
        self.role_arn = "arn:aws:iam::123456789012:role/agent-s3-reader"
        self.region = "us-east-1"
        self.external_id = external_id


class _FakeSts:
    def __init__(self, expiration="2026-07-06T10:15:00+00:00"):
        self.calls = []
        self._expiration = expiration

    async def assume_role(self, access_key_id, secret_access_key, *, role_arn,
                          session_name, duration_seconds, region, external_id):
        self.calls.append(dict(
            access_key_id=access_key_id, secret_access_key=secret_access_key,
            role_arn=role_arn, session_name=session_name,
            duration_seconds=duration_seconds, region=region, external_id=external_id,
        ))
        return {"access_key_id": "ASIA_TEMP", "secret_access_key": "temp-secret",
                "session_token": "temp-token", "expiration": self._expiration}


def test_build_session_name_composes():
    assert build_session_name("claude-code", "s3-reader") == "agentgate-claude-code-s3-reader"


def test_build_session_name_truncates_to_64():
    name = build_session_name("a" * 40, "b" * 40)
    assert len(name) == 64
    assert name.startswith("agentgate-")


def test_build_session_name_rejects_unsafe_after_truncation():
    with pytest.raises(AwsValidationError):
        build_session_name("bad agent", "s3")  # space is outside the STS charset


async def test_assume_role_passes_exact_params_without_external_id():
    ex = _FakeSts()
    cred = await aws_broker.assume_role(
        ex, _Key(), _Res(), ttl_minutes=15, session_name="agentgate-cc-s3",
    )
    assert isinstance(cred, AwsCred)
    assert cred.access_key_id == "ASIA_TEMP"
    assert cred.secret_access_key == "temp-secret"
    assert cred.session_token == "temp-token"
    assert cred.expiration == "2026-07-06T10:15:00+00:00"
    assert cred.region == "us-east-1"
    (call,) = ex.calls
    assert call["access_key_id"] == "AKIA_BROKER"
    assert call["secret_access_key"] == "broker-secret"
    assert call["role_arn"] == "arn:aws:iam::123456789012:role/agent-s3-reader"
    assert call["session_name"] == "agentgate-cc-s3"
    assert call["duration_seconds"] == 15 * 60
    assert call["region"] == "us-east-1"
    assert call["external_id"] is None


async def test_assume_role_forwards_external_id_when_set():
    ex = _FakeSts()
    await aws_broker.assume_role(
        ex, _Key(), _Res(external_id="ext-42"), ttl_minutes=30,
        session_name="agentgate-cc-s3",
    )
    assert ex.calls[0]["external_id"] == "ext-42"
    assert ex.calls[0]["duration_seconds"] == 30 * 60


async def test_assume_role_revalidates_resource_at_the_sink():
    ex = _FakeSts()
    bad = _Res()
    bad.role_arn = "arn:aws:iam::123:role/x"  # bad account id
    with pytest.raises(AwsValidationError):
        await aws_broker.assume_role(ex, _Key(), bad, ttl_minutes=15,
                                     session_name="agentgate-cc-s3")
    assert ex.calls == []  # never called STS with an unvalidated ARN


def test_awscred_secret_fields_not_in_repr():
    cred = AwsCred(access_key_id="ASIA", secret_access_key="SECRET_VALUE",
                   session_token="TOKEN_VALUE", expiration="2026-07-06T10:15:00+00:00",
                   region="us-east-1")
    r = repr(cred)
    assert "SECRET_VALUE" not in r and "TOKEN_VALUE" not in r
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_aws_broker.py -q`
Expected: FAIL with `ModuleNotFoundError: No module named 'broker.aws_broker'`.

- [ ] **Step 3: Implement**

```python
# broker/aws_broker.py
from __future__ import annotations

from dataclasses import dataclass, field

from broker.aws_executor import StsExecutor
from broker.aws_validation import (
    validate_external_id,
    validate_region,
    validate_role_arn,
    validate_session_name,
)

SESSION_PREFIX = "agentgate-"
_MAX_SESSION_NAME = 64


@dataclass(frozen=True)
class AwsCred:
    access_key_id: str
    secret_access_key: str = field(repr=False)
    session_token: str = field(repr=False)
    expiration: str
    region: str


def build_session_name(agent: str, resource: str) -> str:
    """Compose agentgate-<agent>-<resource>, truncate to STS's 64-char limit,
    and sink-validate. Raises AwsValidationError if the result is outside the
    STS RoleSessionName charset (e.g. the agent name carries a space)."""
    name = f"{SESSION_PREFIX}{agent}-{resource}"[:_MAX_SESSION_NAME]
    return validate_session_name(name)


async def assume_role(
    executor: StsExecutor,
    key,
    resource,
    ttl_minutes: int,
    session_name: str,
) -> AwsCred:
    """Re-validate every value that reaches STS at this sink, then assume the
    role. `key` exposes access_key_id/secret_access_key; `resource` exposes
    role_arn/region/external_id — duck-typed so this module never imports the
    stores."""
    role_arn = validate_role_arn(resource.role_arn)
    region = validate_region(resource.region)
    external_id = (
        validate_external_id(resource.external_id)
        if resource.external_id is not None else None
    )
    session_name = validate_session_name(session_name)

    result = await executor.assume_role(
        key.access_key_id,
        key.secret_access_key,
        role_arn=role_arn,
        session_name=session_name,
        duration_seconds=ttl_minutes * 60,
        region=region,
        external_id=external_id,
    )
    return AwsCred(
        access_key_id=result["access_key_id"],
        secret_access_key=result["secret_access_key"],
        session_token=result["session_token"],
        expiration=result["expiration"],
        region=region,
    )
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_aws_broker.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add broker/aws_broker.py tests/test_aws_broker.py
git commit -m "feat: aws_broker session-name build + sink-revalidated assume_role"
```

---

### Task 4: Key store + resource store + config

**Files:**
- Create: `broker/aws_key_store.py`, `broker/aws_resource_store.py`
- Modify: `broker/config.py`
- Test: `tests/test_aws_key_store.py`, `tests/test_aws_resource_store.py`, `tests/test_config.py` (append)

**Interfaces:**
- Consumes: `broker.encrypted_store.EncryptedStore`, `broker.crypto.encrypt/decrypt`.
- Produces:
  - `AwsBrokerKey(access_key_id, secret_access_key)` (frozen; secret `field(repr=False)`); `AwsKeyStore(path, master_password)` with `set(access_key_id, secret_access_key) -> None` (encrypts the secret; overwrite allowed), `load() -> AwsBrokerKey` (KeyError if absent), `is_set() -> bool`.
  - `AwsResource(name, role_arn, region, external_id: str | None, created_at)` (frozen); `AwsResourceStore(path, master_password)` with `store/get/delete/list_names/list_metadata` — same contracts as `DbResourceStore`/`SshResourceStore` (get/delete raise KeyError on unknown).
  - `Config.aws_key_path: str`, `Config.aws_resources_path: str`, `Config.aws_cred_ttl_minutes: int = 15`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_aws_key_store.py
from __future__ import annotations

import pytest

from broker.aws_key_store import AwsBrokerKey, AwsKeyStore


def test_set_load_roundtrip(tmp_path):
    store = AwsKeyStore(str(tmp_path / "k.json"), "pw")
    assert not store.is_set()
    store.set("AKIA_ID", "the-secret")
    assert store.is_set()
    key = store.load()
    assert isinstance(key, AwsBrokerKey)
    assert key.access_key_id == "AKIA_ID"
    assert key.secret_access_key == "the-secret"
    # Fresh instance (new process) decrypts the same secret.
    assert AwsKeyStore(str(tmp_path / "k.json"), "pw").load().secret_access_key == "the-secret"


def test_secret_is_encrypted_on_disk(tmp_path):
    path = tmp_path / "k.json"
    AwsKeyStore(str(path), "pw").set("AKIA_ID", "SENSITIVE_SECRET")
    raw = path.read_text()
    assert "SENSITIVE_SECRET" not in raw
    assert "AKIA_ID" in raw  # access key id is not secret


def test_set_overwrite_allowed(tmp_path):
    # Key rotation is routine — unlike an SSH CA, overwriting is permitted.
    store = AwsKeyStore(str(tmp_path / "k.json"), "pw")
    store.set("AKIA_1", "s1")
    store.set("AKIA_2", "s2")
    assert store.load().access_key_id == "AKIA_2"
    assert store.load().secret_access_key == "s2"


def test_load_before_set_raises_keyerror(tmp_path):
    with pytest.raises(KeyError):
        AwsKeyStore(str(tmp_path / "k.json"), "pw").load()


def test_secret_not_in_repr():
    assert "SENSITIVE" not in repr(AwsBrokerKey(access_key_id="AKIA", secret_access_key="SENSITIVE"))
```

```python
# tests/test_aws_resource_store.py
from __future__ import annotations

import pytest

from broker.aws_resource_store import AwsResource, AwsResourceStore


def _res(name="s3-reader", external_id=None):
    return AwsResource(
        name=name, role_arn="arn:aws:iam::123456789012:role/agent-s3-reader",
        region="us-east-1", external_id=external_id,
        created_at="2026-07-06T10:00:00+00:00",
    )


def test_store_get_roundtrip(tmp_path):
    store = AwsResourceStore(str(tmp_path / "r.json"), "pw")
    store.store(_res(external_id="ext-1"))
    assert store.get("s3-reader") == _res(external_id="ext-1")


def test_get_unknown_raises_keyerror(tmp_path):
    with pytest.raises(KeyError):
        AwsResourceStore(str(tmp_path / "r.json"), "pw").get("nope")


def test_delete_and_list_names(tmp_path):
    store = AwsResourceStore(str(tmp_path / "r.json"), "pw")
    store.store(_res("b"))
    store.store(_res("a"))
    assert store.list_names() == ["a", "b"]
    store.delete("a")
    assert store.list_names() == ["b"]
    with pytest.raises(KeyError):
        store.delete("a")


def test_list_metadata_is_full_record(tmp_path):
    store = AwsResourceStore(str(tmp_path / "r.json"), "pw")
    store.store(_res(external_id="ext-1"))
    (meta,) = store.list_metadata()
    assert meta == {
        "name": "s3-reader",
        "role_arn": "arn:aws:iam::123456789012:role/agent-s3-reader",
        "region": "us-east-1", "external_id": "ext-1",
        "created_at": "2026-07-06T10:00:00+00:00",
    }
```

Append to `tests/test_config.py`:

```python
def test_aws_defaults():
    cfg = Config.from_env({})
    assert cfg.aws_key_path.endswith("aws_key.json")
    assert cfg.aws_resources_path.endswith("aws_resources.json")
    assert cfg.aws_cred_ttl_minutes == 15


def test_aws_cred_ttl_floor_is_15():
    import pytest
    from broker.config import ConfigError
    with pytest.raises(ConfigError):
        Config.from_env({"AWS_CRED_TTL_MINUTES": "14"})
    assert Config.from_env({"AWS_CRED_TTL_MINUTES": "15"}).aws_cred_ttl_minutes == 15
    assert Config.from_env({"AWS_CRED_TTL_MINUTES": "60"}).aws_cred_ttl_minutes == 60


def test_aws_paths_follow_agentgate_home():
    import os
    cfg = Config.from_env({"AGENTGATE_HOME": os.path.join("srv", "ag")})
    assert cfg.aws_key_path == os.path.join("srv", "ag", "aws_key.json")
    assert cfg.aws_resources_path == os.path.join("srv", "ag", "aws_resources.json")
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_aws_key_store.py tests/test_aws_resource_store.py tests/test_config.py -k "aws" -q`
Expected: FAIL (`ModuleNotFoundError` / `AttributeError`).

- [ ] **Step 3: Implement**

```python
# broker/aws_key_store.py
from __future__ import annotations

from dataclasses import dataclass, field

from broker import crypto
from broker.encrypted_store import EncryptedStore


@dataclass(frozen=True)
class AwsBrokerKey:
    access_key_id: str
    secret_access_key: str = field(repr=False)


class AwsKeyStore(EncryptedStore):
    """The broker's dedicated IAM access key. Secret encrypted at rest; the
    access key id is stored readable. Overwriting is allowed — rotating this
    key is routine operator maintenance."""

    _SECTION = "aws_key"
    _KEY = "broker"

    def set(self, access_key_id: str, secret_access_key: str) -> None:
        self._entries()[self._KEY] = {
            "access_key_id": access_key_id,
            "secret_access_key": crypto.encrypt(self._key, secret_access_key),
        }
        self._write(self._data)

    def is_set(self) -> bool:
        return self._KEY in self._entries()

    def load(self) -> AwsBrokerKey:
        entries = self._entries()
        if self._KEY not in entries:
            raise KeyError("aws broker key not set")
        rec = entries[self._KEY]
        return AwsBrokerKey(
            access_key_id=rec["access_key_id"],
            secret_access_key=crypto.decrypt(self._key, rec["secret_access_key"]),
        )
```

```python
# broker/aws_resource_store.py
from __future__ import annotations

from dataclasses import dataclass

from broker.encrypted_store import EncryptedStore


@dataclass(frozen=True)
class AwsResource:
    name: str
    role_arn: str
    region: str
    external_id: str | None
    created_at: str


class AwsResourceStore(EncryptedStore):
    """Registered AWS role resources. Nothing here is secret (the broker key
    lives in AwsKeyStore) — EncryptedStore base buys 0600 perms, atomic
    writes, and per-access disk re-read, not encryption."""

    _SECTION = "aws_resources"

    def store(self, resource: AwsResource) -> None:
        self._entries()[resource.name] = {
            "role_arn": resource.role_arn,
            "region": resource.region,
            "external_id": resource.external_id,
            "created_at": resource.created_at,
        }
        self._write(self._data)

    def get(self, name: str) -> AwsResource:
        entries = self._entries()
        if name not in entries:
            raise KeyError(name)
        rec = entries[name]
        return AwsResource(
            name=name,
            role_arn=rec["role_arn"],
            region=rec["region"],
            external_id=rec["external_id"],
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

`broker/config.py` — three edits (mirror the SSH additions exactly):

Add to `_DEFAULTS`:
```python
    "AWS_CRED_TTL_MINUTES": "15",
```

Add to the dict returned by `_default_paths`:
```python
        "AWS_KEY_PATH": os.path.join(base, "aws_key.json"),
        "AWS_RESOURCES_PATH": os.path.join(base, "aws_resources.json"),
```

Add dataclass fields (after `ssh_cert_ttl_minutes`):
```python
    aws_key_path: str = os.path.join("data", "aws_key.json")
    aws_resources_path: str = os.path.join("data", "aws_resources.json")
    aws_cred_ttl_minutes: int = 15
```

Add to the `cls(...)` call in `from_env` (after the ssh args):
```python
            aws_key_path=_require_non_empty(get("AWS_KEY_PATH"), "AWS_KEY_PATH"),
            aws_resources_path=_require_non_empty(
                get("AWS_RESOURCES_PATH"), "AWS_RESOURCES_PATH"
            ),
            aws_cred_ttl_minutes=_require_int(
                get("AWS_CRED_TTL_MINUTES"), "AWS_CRED_TTL_MINUTES", minimum=15
            ),
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_aws_key_store.py tests/test_aws_resource_store.py tests/test_config.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add broker/aws_key_store.py broker/aws_resource_store.py broker/config.py tests/test_aws_key_store.py tests/test_aws_resource_store.py tests/test_config.py
git commit -m "feat: encrypted AwsKeyStore + AwsResourceStore + config (TTL floor 15)"
```

---

### Task 5: Audit role_arn + broker path + MCP tool + wiring

**Files:**
- Modify: `broker/audit.py`, `broker/mcp_server.py`, `broker/main.py`
- Test: `tests/test_audit.py` (append), `tests/test_aws_tool.py` (create), `tests/test_main.py` (append)

**Interfaces:**
- Consumes: `AwsResourceStore`/`AwsResource` (Task 4), `AwsKeyStore` (Task 4), `aws_broker.build_session_name`/`assume_role` (Task 3), `Boto3StsExecutor`/`StsExecutor` (Task 2), `Config.aws_*` (Task 4), existing `_authenticate`/`_flooded`/`_current_engine`/`ApprovalQueue`.
- Produces: `AuditLogger.log(..., role_arn: str | None = None)`; `Broker.__init__(..., aws_resources=None, aws_key=None, aws_executor=None)`; `Broker.request_aws_credentials(agent, agent_key, resource) -> dict`; MCP tool `aws_credential_request`; `build_broker` wiring. Task 6/7 rely on the tool and wiring.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_audit.py`:

```python
def test_log_accepts_role_arn(tmp_path):
    import json
    from broker.audit import AuditLogger
    path = tmp_path / "audit.log"
    AuditLogger(str(path)).log(
        agent="claude-code", credential_requested="s3-reader", policy_matched="p",
        decision="approved", mode="auto", token_expiry="2026-07-06T10:15:00+00:00",
        role_arn="arn:aws:iam::123456789012:role/agent-s3-reader",
    )
    entry = json.loads(path.read_text().strip())
    assert entry["role_arn"] == "arn:aws:iam::123456789012:role/agent-s3-reader"


def test_log_omits_role_arn_when_absent(tmp_path):
    import json
    from broker.audit import AuditLogger
    path = tmp_path / "audit.log"
    AuditLogger(str(path)).log(
        agent="a", credential_requested="k", policy_matched="p",
        decision="denied", mode="auto", token_expiry=None,
    )
    assert "role_arn" not in json.loads(path.read_text().strip())
```

Create `tests/test_aws_tool.py`:

```python
# tests/test_aws_tool.py
from __future__ import annotations

import json
import textwrap

from broker.agent_store import AgentStore
from broker.approval import ApprovalQueue
from broker.audit import AuditLogger
from broker.aws_key_store import AwsKeyStore
from broker.aws_resource_store import AwsResource, AwsResourceStore
from broker.config import Config
from broker.credential_store import CredentialStore
from broker.mcp_server import Broker, build_mcp
from broker.policy_engine import PolicyEngine

_NULL_FIELDS = ("access_key_id", "secret_access_key", "session_token", "expiration", "region")


class _FakeSts:
    def __init__(self, exc=None):
        self._exc = exc

    async def assume_role(self, access_key_id, secret_access_key, *, role_arn,
                          session_name, duration_seconds, region, external_id):
        if self._exc is not None:
            raise self._exc
        return {"access_key_id": "ASIA_TEMP", "secret_access_key": "TEMP_SECRET_XYZ",
                "session_token": "TEMP_TOKEN_XYZ",
                "expiration": "2026-07-06T10:15:00+00:00"}


def _make_broker(tmp_path, *, policies, with_aws=True, key_set=True, sts=None):
    p = tmp_path / "policies.yaml"
    p.write_text(textwrap.dedent(policies))
    cfg = Config.from_env({
        "POLICIES_PATH": str(p),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTS_PATH": str(tmp_path / "agents.json"),
        "AWS_KEY_PATH": str(tmp_path / "aws_key.json"),
        "AWS_RESOURCES_PATH": str(tmp_path / "aws.json"),
    })
    agents = AgentStore(cfg.agents_path, "pw")
    agent_key = agents.register("claude-code")
    aws_resources = aws_key = None
    if with_aws:
        aws_resources = AwsResourceStore(cfg.aws_resources_path, "pw")
        aws_resources.store(AwsResource(
            name="s3-reader", role_arn="arn:aws:iam::123456789012:role/agent-s3-reader",
            region="us-east-1", external_id=None, created_at="2026-07-06T10:00:00+00:00"))
        aws_key = AwsKeyStore(cfg.aws_key_path, "pw")
        if key_set:
            aws_key.set("AKIA_BROKER", "broker-secret")
    broker = Broker(
        config=cfg,
        store=CredentialStore(cfg.credentials_path, "pw"),
        engine=PolicyEngine.from_file(cfg.policies_path),
        audit=AuditLogger(cfg.logs_path),
        approvals=ApprovalQueue(),
        agents=agents,
        aws_resources=aws_resources,
        aws_key=aws_key,
        aws_executor=sts if sts is not None else _FakeSts(),
    )
    return broker, agent_key, tmp_path / "audit.log"


_ALLOW = """
    policies:
      - name: cc-aws
        agent: claude-code
        credential: s3-reader
        auto_approve: true
        escalate: false
"""

_DENY = """
    policies:
      - name: no-aws
        agent: "*"
        credential: "*"
        auto_approve: false
        escalate: false
"""


def _assert_denied_shape(result):
    assert result["granted"] is False
    for f in _NULL_FIELDS:
        assert result[f] is None, f


async def test_grant_returns_temp_creds_and_audits_without_secrets(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW)
    result = await broker.request_aws_credentials("claude-code", key, "s3-reader")
    assert result["granted"] is True
    assert result["access_key_id"] == "ASIA_TEMP"
    assert result["secret_access_key"] == "TEMP_SECRET_XYZ"
    assert result["session_token"] == "TEMP_TOKEN_XYZ"
    assert result["expiration"] == "2026-07-06T10:15:00+00:00"
    assert result["region"] == "us-east-1"
    log_text = log.read_text()
    entry = json.loads(log_text.strip().splitlines()[-1])
    assert entry["decision"] == "approved"
    assert entry["role_arn"] == "arn:aws:iam::123456789012:role/agent-s3-reader"
    # Secrets must NEVER appear in the audit file.
    assert "TEMP_SECRET_XYZ" not in log_text
    assert "TEMP_TOKEN_XYZ" not in log_text


async def test_unknown_agent_denied_and_never_escalates(tmp_path):
    broker, _key, log = _make_broker(tmp_path, policies=_ALLOW)
    result = await broker.request_aws_credentials("ghost", "bad", "s3-reader")
    _assert_denied_shape(result)
    assert broker.approvals.pending_count() == 0
    assert '"decision": "denied"' in log.read_text()


async def test_policy_hard_deny(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_DENY)
    result = await broker.request_aws_credentials("claude-code", key, "s3-reader")
    _assert_denied_shape(result)
    assert "denied by policy" in result["reason"]
    assert '"decision": "denied"' in log.read_text()


async def test_unknown_resource_fails_closed(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies="""
    policies:
      - name: cc-aws
        agent: claude-code
        credential: "*"
        auto_approve: true
        escalate: false
""")
    result = await broker.request_aws_credentials("claude-code", key, "nope")
    _assert_denied_shape(result)
    assert "unknown aws resource" in result["reason"]
    assert '"decision": "denied"' in log.read_text()


async def test_no_aws_stores_configured_fails_closed(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW, with_aws=False)
    result = await broker.request_aws_credentials("claude-code", key, "s3-reader")
    _assert_denied_shape(result)
    assert '"decision": "denied"' in log.read_text()


async def test_key_not_set_fails_closed(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW, key_set=False)
    result = await broker.request_aws_credentials("claude-code", key, "s3-reader")
    _assert_denied_shape(result)
    assert "aws broker key not set" in result["reason"]
    assert '"decision": "denied"' in log.read_text()


async def test_sts_failure_fails_closed_generic(tmp_path):
    broker, key, log = _make_broker(
        tmp_path, policies=_ALLOW, sts=_FakeSts(exc=RuntimeError("SENSITIVE_STS_DETAIL")))
    result = await broker.request_aws_credentials("claude-code", key, "s3-reader")
    _assert_denied_shape(result)
    assert "SENSITIVE_STS_DETAIL" not in result["reason"]
    assert "could not assume role" in result["reason"]
    log_text = log.read_text()
    assert '"decision": "denied"' in log_text
    assert "SENSITIVE_STS_DETAIL" not in log_text


async def test_key_store_failure_fails_closed_generic(tmp_path):
    broker, key, log = _make_broker(tmp_path, policies=_ALLOW)

    class _Boom:
        def load(self):
            raise RuntimeError("SENSITIVE_KEY_DETAIL")
    broker.aws_key = _Boom()
    result = await broker.request_aws_credentials("claude-code", key, "s3-reader")
    _assert_denied_shape(result)
    assert "SENSITIVE_KEY_DETAIL" not in result["reason"]
    log_text = log.read_text()
    assert '"decision": "denied"' in log_text
    assert "SENSITIVE_KEY_DETAIL" not in log_text


async def test_tool_registered_with_underscore_name(tmp_path):
    from fastmcp import Client
    broker, key, _log = _make_broker(tmp_path, policies=_ALLOW)
    mcp = build_mcp(broker)
    async with Client(mcp) as client:
        names = [t.name for t in await client.list_tools()]
        assert "aws_credential_request" in names
        res = await client.call_tool("aws_credential_request", {
            "agent": "claude-code", "agent_key": key, "resource": "s3-reader"})
        assert res.data["granted"] is True
```

Append to `tests/test_main.py`:

```python
def test_build_broker_wires_aws(tmp_path):
    from broker import main as m
    cfg = Config.from_env({
        "POLICIES_PATH": str(tmp_path / "p.yaml"),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "AGENTS_PATH": str(tmp_path / "agents.json"),
        "AWS_KEY_PATH": str(tmp_path / "aws_key.json"),
        "AWS_RESOURCES_PATH": str(tmp_path / "aws.json"),
    })
    (tmp_path / "p.yaml").write_text(
        'policies:\n  - name: d\n    agent: "*"\n    credential: "*"\n'
        "    auto_approve: false\n    escalate: true\n")
    broker = m.build_broker(cfg, "pw")
    assert broker.aws_resources is not None
    assert broker.aws_key is not None
    assert broker.aws_executor is not None
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_aws_tool.py tests/test_audit.py tests/test_main.py -q`
Expected: FAIL (`AttributeError`/`TypeError`: no `request_aws_credentials`, unknown `role_arn`/`aws_*` kwargs).

- [ ] **Step 3: Implement**

`broker/audit.py` — add parameter after `key_id`:
```python
        role_arn: str | None = None,
```
and after the `key_id` inclusion block:
```python
        if role_arn is not None:
            entry["role_arn"] = role_arn
```

`broker/mcp_server.py`:

Imports (with the other `broker.` imports):
```python
from broker import aws_broker
from broker.aws_executor import StsExecutor
from broker.aws_key_store import AwsKeyStore
from broker.aws_resource_store import AwsResourceStore
```

`Broker.__init__` — add params after `ssh_ca`:
```python
        aws_resources: AwsResourceStore | None = None,
        aws_key: AwsKeyStore | None = None,
        aws_executor: StsExecutor | None = None,
```
and assignments after `self.ssh_ca = ssh_ca`:
```python
        self.aws_resources = aws_resources
        self.aws_key = aws_key
        self.aws_executor = aws_executor
```

Add after `_escalate_ssh` (mirrors the ssh path exactly):

```python
    @staticmethod
    def _aws_deny(reason: str) -> dict:
        return {
            "granted": False, "access_key_id": None, "secret_access_key": None,
            "session_token": None, "expiration": None, "region": None,
            "reason": reason,
        }

    async def request_aws_credentials(self, agent: str, agent_key: str, resource: str) -> dict:
        self.total_requests += 1
        mode = state.read_mode(self.config.state_path)

        if not self._authenticate(agent, agent_key, resource, mode):
            return self._aws_deny("unknown agent or invalid agent key")

        if mode == "manual":
            return await self._escalate_aws(agent, resource, mode, "manual-mode")

        decision = self._current_engine().evaluate(agent, resource)
        if decision.auto_approve:
            return await self._grant_aws(agent, resource, mode, decision.policy_name)
        if not decision.escalate:
            self.audit.log(
                agent=agent, credential_requested=resource,
                policy_matched=decision.policy_name, decision="denied",
                mode=mode, token_expiry=None,
            )
            return self._aws_deny(f"denied by policy '{decision.policy_name}'")
        return await self._escalate_aws(agent, resource, mode, decision.policy_name)

    async def _grant_aws(self, agent: str, resource: str, mode: str, policy_name: str) -> dict:
        if self.aws_resources is None:
            res = None
        else:
            try:
                res = self.aws_resources.get(resource)
            except KeyError:
                res = None
            except Exception:
                self.audit.log(
                    agent=agent, credential_requested=resource, policy_matched=policy_name,
                    decision="denied", mode=mode, token_expiry=None,
                )
                return self._aws_deny(f"could not access aws resource '{resource}'")
        if res is None or self.aws_key is None or self.aws_executor is None:
            self.audit.log(
                agent=agent, credential_requested=resource, policy_matched=policy_name,
                decision="denied", mode=mode, token_expiry=None,
            )
            return self._aws_deny(f"unknown aws resource '{resource}'")

        try:
            key = self.aws_key.load()
        except KeyError:
            self.audit.log(
                agent=agent, credential_requested=resource, policy_matched=policy_name,
                decision="denied", mode=mode, token_expiry=None,
            )
            return self._aws_deny("aws broker key not set")
        except Exception:
            self.audit.log(
                agent=agent, credential_requested=resource, policy_matched=policy_name,
                decision="denied", mode=mode, token_expiry=None,
            )
            return self._aws_deny("could not access aws broker key")

        try:
            session_name = aws_broker.build_session_name(agent, resource)
            cred = await aws_broker.assume_role(
                self.aws_executor, key, res,
                self.config.aws_cred_ttl_minutes, session_name,
            )
        except Exception:
            # Fail closed: never leak the boto3/validation error (which can embed
            # ARNs/request IDs); always audit.
            self.audit.log(
                agent=agent, credential_requested=resource, policy_matched=policy_name,
                decision="denied", mode=mode, token_expiry=None,
            )
            return self._aws_deny(f"could not assume role for '{resource}'")

        self.audit.log(
            agent=agent, credential_requested=resource, policy_matched=policy_name,
            decision="approved", mode=mode, token_expiry=cred.expiration,
            role_arn=res.role_arn,
        )
        return {
            "granted": True, "access_key_id": cred.access_key_id,
            "secret_access_key": cred.secret_access_key,
            "session_token": cred.session_token, "expiration": cred.expiration,
            "region": cred.region,
            "reason": f"auto-approved by policy '{policy_name}'",
        }

    async def _escalate_aws(self, agent: str, resource: str, mode: str, policy_name: str) -> dict:
        if self._flooded(agent, resource, mode, policy_name):
            return self._aws_deny("too many requests pending operator approval")
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
            return self._aws_deny("escalation timed out")
        if approved:
            return await self._grant_aws(agent, resource, mode, f"manual:{policy_name}")
        self.audit.log(
            agent=agent, credential_requested=resource, policy_matched=policy_name,
            decision="denied", mode=mode, token_expiry=None,
        )
        return self._aws_deny("denied by operator")
```

In `build_mcp`, after the `ssh_certificate_request` tool (before `return mcp`):

```python
    @mcp.tool(name="aws_credential_request")
    async def aws_credential_request(agent: str, agent_key: str, resource: str) -> dict:
        return await broker.request_aws_credentials(agent, agent_key, resource)
```

`broker/main.py` — imports:
```python
from broker.aws_executor import Boto3StsExecutor
from broker.aws_key_store import AwsKeyStore
from broker.aws_resource_store import AwsResourceStore
```
and in `build_broker`'s `Broker(...)` call, after `ssh_ca=SshCaStore(...)`:
```python
        aws_resources=AwsResourceStore(config.aws_resources_path, master_password),
        aws_key=AwsKeyStore(config.aws_key_path, master_password),
        aws_executor=Boto3StsExecutor(),
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_aws_tool.py tests/test_audit.py tests/test_main.py -q`
Expected: PASS. Then the full suite: `python -m pytest -q` — all pass, no regressions.

- [ ] **Step 5: Commit**

```bash
git add broker/audit.py broker/mcp_server.py broker/main.py tests/test_aws_tool.py tests/test_audit.py tests/test_main.py
git commit -m "feat: aws_credential_request broker path + MCP tool; audit role_arn"
```

---

### Task 6: CLI `aws-key-set` / `aws-add` / `aws-list` / `aws-remove`

**Files:**
- Modify: `cli/commands.py`
- Test: `tests/test_aws_cli.py`

**Interfaces:**
- Consumes: `AwsKeyStore` (Task 4), `AwsResource`/`AwsResourceStore` (Task 4), `validate_role_arn`/`validate_region`/`validate_external_id`/`AwsValidationError` (Task 1), existing `_password`, `build_parser`, `run`, `AuditLogger`.
- Produces: four subcommands. `aws-key-set` audited `log_operator(action="aws-key-set", subject="aws-broker-key")`; `aws-add`/`aws-remove` audited with the resource name. Secret via env → getpass → stdin, never argv; empty secret → exit 2. Invalid ARN/region/external-id → exit 2, nothing stored. Unknown remove → exit 1, no audit row.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_aws_cli.py
from __future__ import annotations

import io
import textwrap

from broker.aws_key_store import AwsKeyStore
from broker.aws_resource_store import AwsResourceStore
from broker.config import Config
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
        "AWS_KEY_PATH": str(tmp_path / "aws_key.json"),
        "AWS_RESOURCES_PATH": str(tmp_path / "aws.json"),
    })


def test_aws_key_set_from_env(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path)
    monkeypatch.setenv("AGENTGATE_AWS_SECRET_KEY", "the-secret")
    rc = commands.run(["aws-key-set", "AKIA_ID"], config=cfg, master_password="pw")
    assert rc == 0
    key = AwsKeyStore(cfg.aws_key_path, "pw").load()
    assert key.access_key_id == "AKIA_ID"
    assert key.secret_access_key == "the-secret"
    out = capsys.readouterr().out
    assert "the-secret" not in out
    log = (tmp_path / "audit.log").read_text()
    assert '"action": "aws-key-set"' in log
    assert "the-secret" not in log


def test_aws_key_set_rejects_empty_secret(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    monkeypatch.delenv("AGENTGATE_AWS_SECRET_KEY", raising=False)
    monkeypatch.setattr(commands.sys, "stdin", io.StringIO(""))
    monkeypatch.setattr(commands.sys.stdin, "isatty", lambda: False, raising=False)
    rc = commands.run(["aws-key-set", "AKIA_ID"], config=cfg, master_password="pw")
    assert rc == 2
    assert not AwsKeyStore(cfg.aws_key_path, "pw").is_set()
    assert '"action": "aws-key-set"' not in (tmp_path / "audit.log").read_text()


def test_aws_add_list_remove(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    rc = commands.run([
        "aws-add", "s3-reader",
        "--role-arn", "arn:aws:iam::123456789012:role/agent-s3-reader",
        "--region", "us-east-1", "--external-id", "ext-1",
    ], config=cfg, master_password="pw")
    assert rc == 0
    res = AwsResourceStore(cfg.aws_resources_path, "pw").get("s3-reader")
    assert res.role_arn == "arn:aws:iam::123456789012:role/agent-s3-reader"
    assert res.region == "us-east-1"
    assert res.external_id == "ext-1"

    assert commands.run(["aws-list"], config=cfg, master_password="pw") == 0
    out = capsys.readouterr().out
    assert "s3-reader" in out and "us-east-1" in out

    assert commands.run(["aws-remove", "s3-reader"], config=cfg, master_password="pw") == 0
    assert AwsResourceStore(cfg.aws_resources_path, "pw").list_names() == []

    log = (tmp_path / "audit.log").read_text()
    assert '"action": "aws-add"' in log and '"action": "aws-remove"' in log


def test_aws_add_without_external_id(tmp_path):
    cfg = _cfg(tmp_path)
    rc = commands.run([
        "aws-add", "s3", "--role-arn", "arn:aws:iam::123456789012:role/r",
        "--region", "eu-west-1",
    ], config=cfg, master_password="pw")
    assert rc == 0
    assert AwsResourceStore(cfg.aws_resources_path, "pw").get("s3").external_id is None


def test_aws_add_rejects_bad_arn(tmp_path):
    cfg = _cfg(tmp_path)
    rc = commands.run([
        "aws-add", "bad", "--role-arn", "arn:aws:iam::123:role/r", "--region", "us-east-1",
    ], config=cfg, master_password="pw")
    assert rc == 2
    assert AwsResourceStore(cfg.aws_resources_path, "pw").list_names() == []
    log_path = tmp_path / "audit.log"
    if log_path.exists():
        assert '"action": "aws-add"' not in log_path.read_text()


def test_aws_remove_unknown_fails(tmp_path):
    cfg = _cfg(tmp_path)
    assert commands.run(["aws-remove", "nope"], config=cfg, master_password="pw") == 1
    log_path = tmp_path / "audit.log"
    if log_path.exists():
        assert '"action": "aws-remove"' not in log_path.read_text()
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_aws_cli.py -q`
Expected: FAIL (`SystemExit: 2` from argparse — unknown subcommand `aws-key-set`).

- [ ] **Step 3: Implement**

In `cli/commands.py`, add imports:

```python
from broker.aws_key_store import AwsKeyStore
from broker.aws_resource_store import AwsResource, AwsResourceStore
from broker.aws_validation import (
    AwsValidationError,
    validate_external_id,
    validate_region,
    validate_role_arn,
)
```

In `build_parser`, after the `ssh-remove` subparser:

```python
    ak = sub.add_parser("aws-key-set", help="store the broker's IAM access key (secret not via argv)")
    ak.add_argument("access_key_id")
    aa = sub.add_parser("aws-add", help="register an AWS role resource")
    aa.add_argument("name")
    aa.add_argument("--role-arn", required=True, dest="role_arn")
    aa.add_argument("--region", required=True)
    aa.add_argument("--external-id", default=None, dest="external_id")
    sub.add_parser("aws-list", help="list registered AWS resources")
    ar = sub.add_parser("aws-remove", help="remove an AWS resource")
    ar.add_argument("name")
```

In `run`, before the final `return 2`:

```python
    if args.command == "aws-key-set":
        secret = os.environ.get("AGENTGATE_AWS_SECRET_KEY")
        if not secret:
            secret = (
                getpass.getpass("AWS secret access key: ")
                if sys.stdin.isatty() else sys.stdin.readline().rstrip("\n")
            )
        if not secret:
            print("AWS secret access key must not be empty", file=sys.stderr)
            return 2
        AwsKeyStore(config.aws_key_path, _password(master_password)).set(
            args.access_key_id, secret
        )
        AuditLogger(config.logs_path).log_operator(
            action="aws-key-set", subject="aws-broker-key"
        )
        print("stored aws broker key")
        return 0

    if args.command == "aws-add":
        try:
            role_arn = validate_role_arn(args.role_arn)
            region = validate_region(args.region)
            external_id = (
                validate_external_id(args.external_id)
                if args.external_id is not None else None
            )
        except AwsValidationError as exc:
            print(f"invalid aws resource: {exc}", file=sys.stderr)
            return 2
        AwsResourceStore(config.aws_resources_path, _password(master_password)).store(
            AwsResource(
                name=args.name, role_arn=role_arn, region=region,
                external_id=external_id,
                created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(
                    timespec="seconds"
                ),
            )
        )
        AuditLogger(config.logs_path).log_operator(action="aws-add", subject=args.name)
        print(f"registered aws resource '{args.name}'")
        return 0

    if args.command == "aws-list":
        store = AwsResourceStore(config.aws_resources_path, _password(master_password))
        for meta in store.list_metadata():
            ext = f"  external-id: {meta['external_id']}" if meta["external_id"] else ""
            print(f"{meta['name']}  {meta['role_arn']}  ({meta['region']}){ext}")
        return 0

    if args.command == "aws-remove":
        store = AwsResourceStore(config.aws_resources_path, _password(master_password))
        try:
            store.delete(args.name)
        except KeyError:
            print(f"no such aws resource '{args.name}'", file=sys.stderr)
            return 1
        AuditLogger(config.logs_path).log_operator(action="aws-remove", subject=args.name)
        print(f"removed aws resource '{args.name}'")
        return 0
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_aws_cli.py -q`
Expected: PASS. Then `python -m pytest -q` — all pass, no regressions.

- [ ] **Step 5: Commit**

```bash
git add cli/commands.py tests/test_aws_cli.py
git commit -m "feat: CLI aws-key-set/aws-add/aws-list/aws-remove with operator audit"
```

---

### Task 7: Dependency, docs, integration test

**Files:**
- Modify: `requirements.txt`, `pyproject.toml`, `.env.example`, `README.md`
- Create: `tests/test_aws_integration.py`

**Interfaces:**
- Consumes: everything above.
- Produces: `boto3` dependency; AWS-broker docs; a skip-gated real-STS integration test.

- [ ] **Step 1: Write the integration test (skip-gated)**

```python
# tests/test_aws_integration.py
from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("AGENTGATE_TEST_AWS_ROLE_ARN"),
    reason=(
        "set AGENTGATE_TEST_AWS_ROLE_ARN (and AGENTGATE_TEST_AWS_ACCESS_KEY_ID / "
        "AGENTGATE_TEST_AWS_SECRET_KEY / optionally AGENTGATE_TEST_AWS_REGION, "
        "AGENTGATE_TEST_AWS_EXTERNAL_ID) to run against real STS"
    ),
)


async def test_assume_role_against_real_sts():
    import boto3

    from broker.aws_broker import assume_role, build_session_name
    from broker.aws_executor import Boto3StsExecutor
    from broker.aws_key_store import AwsBrokerKey
    from broker.aws_resource_store import AwsResource

    region = os.environ.get("AGENTGATE_TEST_AWS_REGION", "us-east-1")
    key = AwsBrokerKey(
        access_key_id=os.environ["AGENTGATE_TEST_AWS_ACCESS_KEY_ID"],
        secret_access_key=os.environ["AGENTGATE_TEST_AWS_SECRET_KEY"],
    )
    resource = AwsResource(
        name="itest", role_arn=os.environ["AGENTGATE_TEST_AWS_ROLE_ARN"],
        region=region, external_id=os.environ.get("AGENTGATE_TEST_AWS_EXTERNAL_ID"),
        created_at="2026-07-06T10:00:00+00:00",
    )
    session_name = build_session_name("itest-agent", "itest")

    cred = await assume_role(
        Boto3StsExecutor(), key, resource, ttl_minutes=15, session_name=session_name,
    )

    # The returned credentials work and identify as the assumed role + session.
    sts = boto3.client(
        "sts", region_name=region,
        aws_access_key_id=cred.access_key_id,
        aws_secret_access_key=cred.secret_access_key,
        aws_session_token=cred.session_token,
    )
    ident = sts.get_caller_identity()
    assert session_name in ident["Arn"]
    assert "assumed-role" in ident["Arn"]


async def test_wrong_external_id_is_refused():
    role_arn = os.environ.get("AGENTGATE_TEST_AWS_ROLE_ARN")
    if not os.environ.get("AGENTGATE_TEST_AWS_EXTERNAL_ID"):
        pytest.skip("role does not require an ExternalId; nothing to refuse")

    from broker.aws_broker import assume_role, build_session_name
    from broker.aws_executor import Boto3StsExecutor
    from broker.aws_key_store import AwsBrokerKey
    from broker.aws_resource_store import AwsResource

    region = os.environ.get("AGENTGATE_TEST_AWS_REGION", "us-east-1")
    key = AwsBrokerKey(
        access_key_id=os.environ["AGENTGATE_TEST_AWS_ACCESS_KEY_ID"],
        secret_access_key=os.environ["AGENTGATE_TEST_AWS_SECRET_KEY"],
    )
    resource = AwsResource(
        name="itest", role_arn=role_arn, region=region,
        external_id="wrong-external-id", created_at="2026-07-06T10:00:00+00:00",
    )
    with pytest.raises(Exception):  # STS AccessDenied
        await assume_role(Boto3StsExecutor(), key, resource, ttl_minutes=15,
                          session_name=build_session_name("itest-agent", "itest"))
```

- [ ] **Step 2: Run to verify it skips cleanly**

Run: `python -m pytest tests/test_aws_integration.py -q`
Expected: `2 skipped` (no `AGENTGATE_TEST_AWS_ROLE_ARN` set).

- [ ] **Step 3: Add dependency + docs**

`requirements.txt` — add:
```
boto3>=1.34
```

`pyproject.toml` — add `"boto3>=1.34",` to the `dependencies` list.

`.env.example` — add after the SSH broker block:
```
# AWS broker: encrypted broker-key + resource store paths and credential TTL.
# One-time: `agentgate aws-key-set <access-key-id>` (secret via
# AGENTGATE_AWS_SECRET_KEY / prompt / stdin, never argv), then register roles
# with `agentgate aws-add`.
# AWS_KEY_PATH=./data/aws_key.json
# AWS_RESOURCES_PATH=./data/aws_resources.json
AWS_CRED_TTL_MINUTES=15

# Set ONLY when running `agentgate aws-key-set` (read at set time, stored
# encrypted; never a command-line argument):
# AGENTGATE_AWS_SECRET_KEY=
```

`README.md`:
1. In the `## MCP Tools` intro: change "8 MCP tools" → "9 MCP tools" and "The five that grant or change anything" → "The six that grant or change anything".
2. Add a numbered entry for **`aws_credential_request(agent, agent_key, resource)`** — returns `{granted, access_key_id, secret_access_key, session_token, expiration, region, reason}`; when denied all credential fields are `null`. Note the granted keys ARE working (TTL-limited) AWS credentials — treat the response as secret.
3. Add a `## AWS Broker` section after the SSH Broker section covering: the model (STS AssumeRole; credentials short-lived, scoped by the IAM role, expire natively — no reaper); one-time setup — create scoped IAM roles, create a dedicated broker IAM user whose ONLY policy is `sts:AssumeRole` on those role ARNs (include the exact inline policy JSON: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":["arn:aws:iam::123456789012:role/agent-s3-reader"]}]}`), `agentgate aws-key-set <access-key-id>`; registering roles (`agentgate aws-add s3-reader --role-arn ... --region us-east-1 [--external-id X]`); the tool + response shape; that the RoleSessionName `agentgate-<agent>-<resource>` appears in CloudTrail so every AWS action traces to an agent; TTL default 15 min (STS floor); residual-risk note — AgentGate holds an IAM key that can assume every registered role (mitigated by the AssumeRole-only policy, encryption at rest, and CloudTrail attribution); no pre-expiry revocation of issued STS credentials — TTL is the control.
4. Add `AWS_KEY_PATH`, `AWS_RESOURCES_PATH`, `AWS_CRED_TTL_MINUTES` to the `## ECS Migration` section, matching the existing style.

- [ ] **Step 4: Run the full suite**

Run: `python -m pytest -q`
Expected: PASS (all prior tests plus the new ones; AWS + DB + SSH + OAuth integration tests skipped).

- [ ] **Step 5: Commit**

```bash
git add requirements.txt pyproject.toml .env.example README.md tests/test_aws_integration.py
git commit -m "feat: boto3 dependency, AWS broker docs, skip-gated real-STS integration test"
```

---

## Self-Review

**Spec coverage:**
- STS AssumeRole, temporary keypair + session token → Tasks 2, 3, 5. ✓
- Broker's own IAM key encrypted at rest, overwrite allowed → Task 4 (`AwsKeyStore`). ✓
- Scoping via the IAM role; resource = name + role ARN + region + optional ExternalId → Task 4 (`AwsResource`). ✓
- RoleSessionName `agentgate-<agent>-<resource>`, sink-validated + truncated → Task 3 (`build_session_name`), Task 5 (call site). ✓
- TTL = minutes×60, default 15 / floor 15 → Task 3 (duration), Task 4 (config `minimum=15`). ✓
- No reaper → none anywhere. ✓
- boto3 lazy, explicit-keys-only, to_thread, injectable → Task 2. ✓
- Validate at input AND sink, canonical leaf module → Task 1, Task 3 (sink), Task 6 (input). ✓
- Broker path mirrors ssh path; all fail-closed rows from the spec's error table (key-not-set, decrypt/store/STS failure generic, unknown resource, no-stores, auth-before-escalation, flood, timeout, operator deny) → Task 5 (each tested). ✓
- Audit role_arn/expiry only, secrets never audited → Task 5 (audit param + marker-string absence tests). ✓
- Tool `aws_credential_request`, 9 tools / 6 grant-or-change → Tasks 5, 7. ✓
- CLI four subcommands + operator audit + exit codes from the spec's error table → Task 6. ✓
- Skip-gated integration test (real AssumeRole, creds work + session name in caller identity, wrong ExternalId refused) → Task 7. ✓
- Out-of-scope items (session policies, ambient chain, federation, key rotation automation) → correctly absent. ✓

**Placeholder scan:** none — every code step carries complete code; the only prose step is Task 7's README content, which enumerates exact required text, numbers, and the literal IAM policy JSON.

**Type consistency:** `AwsCred(access_key_id, secret_access_key, session_token, expiration, region)` (Task 3) matches `_grant_aws`'s `cred.*` reads and the response keys (Task 5). `AwsResource(name, role_arn, region, external_id, created_at)` consistent across Tasks 3, 4, 5, 6. `AwsBrokerKey(access_key_id, secret_access_key)` consistent across Tasks 3, 4, 5. `AwsKeyStore.set/load/is_set` consistent (Tasks 4, 5, 6). `StsExecutor.assume_role(...)` signature identical across Tasks 2, 3 (and the fakes). `validate_role_arn/validate_region/validate_external_id/validate_session_name` consistent across Tasks 1, 3, 6. Deny-shape keys identical between `_aws_deny` (Task 5) and the tests' `_NULL_FIELDS`. `aws_cred_ttl_minutes` from config flows into `duration_seconds = ttl×60`.

**Notes for implementers:** pytest runs with `asyncio_mode = auto` — async tests need no decorator. Task 3 is implemented before Task 4, so `aws_broker.py` must NOT import the stores — it duck-types `key`/`resource` attributes (the plan's code and tests already reflect this). boto3 is NOT installed in the dev env until Task 7; every unit test must run without it (only the skip-gated integration test and the lazy executor import boto3).
