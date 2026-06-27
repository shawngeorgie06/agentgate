# Escalation Timeout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional, opt-in timeout that bounds how long an escalated credential/policy request waits for operator approval; when it fires the request fails closed (deny), so headless deployments don't hang forever.

**Architecture:** A new `ESCALATION_TIMEOUT_SECONDS` config field flows into `ApprovalQueue.submit(..., timeout=...)`, which wraps the approval `Future` in `asyncio.wait_for` and re-raises `asyncio.TimeoutError` after removing the request. `Broker._escalate` and `Broker.add_policy` pass the configured timeout and catch the timeout to fail closed, auditing credential timeouts as a new `"expired"` decision.

**Tech Stack:** Python 3.11+, asyncio, pytest + pytest-asyncio (asyncio_mode=auto), existing AgentGate modules.

## Global Constraints

- Python 3.11+. No hardcoded paths — config comes from env via `Config`.
- `0` / unset `ESCALATION_TIMEOUT_SECONDS` = disabled = wait forever (exact current behavior). Only `> 0` bounds the wait.
- Timeout fails **closed**: on timeout no token is issued, no credential value is returned, and `policies.yaml` is never modified.
- The timeout applies uniformly to credential-request escalations AND `policy.add`.
- Credentials and tokens are never logged (unchanged invariant).
- This module set uses `from __future__ import annotations` and `typing.Optional` style (not PEP 604) — match the surrounding file's existing style in each edit.
- Full suite must stay green and pristine (`python -m pytest -v`) before each commit. Run from repo root `C:\Users\georg\agentgate`. Python is `python`; tests via `python -m pytest`.
- Commit approach for this work is per the operator's confirmed instruction at execution start (the AgentGate build allows one commit per task; do not push or use `--no-verify`). End every commit message with a blank line then exactly:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`

---

## File Structure

| File | Change |
|------|--------|
| `broker/config.py` | Add `escalation_timeout_seconds: int` field + `ESCALATION_TIMEOUT_SECONDS` default |
| `broker/audit.py` | Add `"expired"` to `_VALID_DECISIONS` |
| `.env.example` | Document `ESCALATION_TIMEOUT_SECONDS` |
| `broker/approval.py` | `ApprovalQueue.submit` gains `timeout` kwarg |
| `broker/mcp_server.py` | `_escalate` + `add_policy` pass timeout, catch `asyncio.TimeoutError` (add `import asyncio`) |
| `README.md` | Config table + audit decision values |
| `tests/test_config.py`, `tests/test_audit.py`, `tests/test_approval.py`, `tests/test_mcp_server.py` | Coverage |

Three tasks: (1) config + audit foundations + .env.example, (2) queue timeout, (3) broker wiring + README.

---

## Task 1: Config + audit foundations

**Files:**
- Modify: `broker/config.py`
- Modify: `broker/audit.py:8`
- Modify: `.env.example`
- Test: `tests/test_config.py`, `tests/test_audit.py`

**Interfaces:**
- Produces: `Config.escalation_timeout_seconds: int` (from env `ESCALATION_TIMEOUT_SECONDS`, default `0`). `audit.AuditLogger.log(..., decision="expired", ...)` is now valid.

- [ ] **Step 1: Write the failing config test**

Add to `tests/test_config.py`:

```python
def test_escalation_timeout_defaults_to_zero():
    assert Config.from_env({}).escalation_timeout_seconds == 0


def test_escalation_timeout_reads_override():
    cfg = Config.from_env({"ESCALATION_TIMEOUT_SECONDS": "30"})
    assert cfg.escalation_timeout_seconds == 30
```

- [ ] **Step 2: Write the failing audit test**

Add to `tests/test_audit.py`:

```python
def test_log_accepts_expired_decision(tmp_path):
    path = str(tmp_path / "audit.log")
    logger = AuditLogger(path)
    logger.log(
        agent="claude-code",
        credential_requested="anthropic-api-key",
        policy_matched="cc-anthropic",
        decision="expired",
        mode="auto",
        token_expiry=None,
    )  # must not raise
    import json
    entry = json.loads((tmp_path / "audit.log").read_text().strip().splitlines()[-1])
    assert entry["decision"] == "expired"
```

- [ ] **Step 3: Run both tests to verify they fail**

Run: `python -m pytest tests/test_config.py -k escalation tests/test_audit.py -k expired -v`
Expected: FAIL — `AttributeError: 'Config' object has no attribute 'escalation_timeout_seconds'` and `ValueError` for the `"expired"` decision.

- [ ] **Step 4: Add the config field**

In `broker/config.py`, add to `_DEFAULTS` (after the `TOKEN_TTL_MINUTES` entry):

```python
    "ESCALATION_TIMEOUT_SECONDS": "0",
```

Add the dataclass field (after `token_ttl_minutes: int`):

```python
    escalation_timeout_seconds: int
```

And in `from_env`'s returned `cls(...)`, add (after `token_ttl_minutes=int(get("TOKEN_TTL_MINUTES")),`):

```python
            escalation_timeout_seconds=int(get("ESCALATION_TIMEOUT_SECONDS")),
```

- [ ] **Step 5: Add the audit decision value**

In `broker/audit.py:8`, change:

```python
_VALID_DECISIONS = {"approved", "denied", "escalated"}
```

to:

```python
_VALID_DECISIONS = {"approved", "denied", "escalated", "expired"}
```

- [ ] **Step 6: Document the env var**

In `.env.example`, after the `TOKEN_TTL_MINUTES=60` block, add:

```
# Seconds to wait for operator approval on an escalated request before
# failing closed (denying). 0 = disabled (wait indefinitely) — the default,
# matching interactive CLI use. Set > 0 for headless/unattended deployments.
ESCALATION_TIMEOUT_SECONDS=0
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `python -m pytest tests/test_config.py tests/test_audit.py -v`
Expected: PASS (all config + audit tests, including the two new ones).

- [ ] **Step 8: Run the full suite**

Run: `python -m pytest -q`
Expected: all pass (was 43; now 45), pristine.

- [ ] **Step 9: Commit**

```bash
git add broker/config.py broker/audit.py .env.example tests/test_config.py tests/test_audit.py
git commit -m "feat: add ESCALATION_TIMEOUT_SECONDS config + expired audit decision"
```
(Append the Co-Authored-By trailer per Global Constraints.)

---

## Task 2: ApprovalQueue.submit timeout

**Files:**
- Modify: `broker/approval.py`
- Test: `tests/test_approval.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `async ApprovalQueue.submit(self, agent: str, credential: str, timeout: Optional[float] = None) -> bool`. With `timeout=None`, awaits indefinitely (unchanged). With `timeout` set and no resolution in time, removes the request from the queue and raises `asyncio.TimeoutError`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_approval.py`:

```python
import asyncio
import pytest
from broker.approval import ApprovalQueue


async def test_submit_times_out_and_removes_request():
    q = ApprovalQueue()
    with pytest.raises(asyncio.TimeoutError):
        await q.submit("claude-code", "anthropic-api-key", timeout=0.01)
    assert q.pending_count() == 0


async def test_submit_with_timeout_resolved_in_time_returns_value():
    q = ApprovalQueue()
    task = asyncio.create_task(q.submit("a", "k", timeout=5))
    await asyncio.sleep(0)
    pending = q.get_pending()
    assert pending is not None
    q.resolve(pending, True)
    assert await task is True
    assert q.pending_count() == 0
```

(`asyncio` / `pytest` may already be imported at the top of the file — reuse the existing imports rather than duplicating.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_approval.py -k timeout -v`
Expected: FAIL — `TypeError: submit() got an unexpected keyword argument 'timeout'`.

- [ ] **Step 3: Implement the timeout in `submit`**

In `broker/approval.py`, replace the `submit` method:

```python
    async def submit(self, agent: str, credential: str) -> bool:
        loop = asyncio.get_running_loop()
        req = PendingRequest(agent=agent, credential=credential, future=loop.create_future())
        self._queue.append(req)
        return await req.future
```

with:

```python
    async def submit(
        self, agent: str, credential: str, timeout: Optional[float] = None
    ) -> bool:
        loop = asyncio.get_running_loop()
        req = PendingRequest(agent=agent, credential=credential, future=loop.create_future())
        self._queue.append(req)
        if timeout is None:
            return await req.future
        try:
            return await asyncio.wait_for(req.future, timeout)
        except asyncio.TimeoutError:
            # Fail closed: drop the request so it never lingers as phantom-pending.
            self._remove(req)
            raise
```

Add a small private helper next to `resolve` (it factors the existing removal logic so both paths stay consistent):

```python
    def _remove(self, request: PendingRequest) -> None:
        try:
            self._queue.remove(request)
        except ValueError:
            pass
```

And update `resolve` to reuse it (replace its `try/except ValueError` block):

```python
    def resolve(self, request: PendingRequest, approved: bool) -> None:
        if not request.future.done():
            request.future.set_result(approved)
        self._remove(request)
```

(`Optional` is already imported from `typing` at the top of `broker/approval.py`.)

- [ ] **Step 4: Run the new tests to verify they pass**

Run: `python -m pytest tests/test_approval.py -k timeout -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Run the full approval suite + full suite**

Run: `python -m pytest tests/test_approval.py -v && python -m pytest -q`
Expected: all existing approval tests still pass (the `timeout=None` default preserves behavior); full suite green (now 47), pristine.

- [ ] **Step 6: Commit**

```bash
git add broker/approval.py tests/test_approval.py
git commit -m "feat: optional timeout for ApprovalQueue.submit (fail closed)"
```
(Append the Co-Authored-By trailer.)

---

## Task 3: Broker wiring + README

**Files:**
- Modify: `broker/mcp_server.py` (add `import asyncio`; `_escalate`; `add_policy`)
- Modify: `README.md`
- Test: `tests/test_mcp_server.py`

**Interfaces:**
- Consumes: `Config.escalation_timeout_seconds` (Task 1), `ApprovalQueue.submit(..., timeout=...)` raising `asyncio.TimeoutError` (Task 2), audit `"expired"` (Task 1).
- Produces: on timeout, `request_credential`/`_escalate` returns `{"granted": False, "token": None, "token_expiry": None, "value": None, "reason": "escalation timed out"}` and audits `decision="expired"`; `add_policy` returns `{"added": False, "reason": "policy change escalation timed out"}` with `policies.yaml` unchanged.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_mcp_server.py` (reuse the existing `_make_broker` helper and `_AUTO_POLICY`). The broker config is overridden with a fractional `escalation_timeout_seconds` via `dataclasses.replace` so the tests time out in well under a second — the field is typed `int` but is only passed through to `asyncio.wait_for`, which accepts a float, and nothing coerces it at runtime:

```python
import dataclasses


async def test_escalation_times_out_and_denies(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    broker.config = dataclasses.replace(broker.config, escalation_timeout_seconds=0.01)
    # "evil" agent doesn't match the auto-approve policy -> escalates; no operator resolves it.
    res = await broker.request_credential("evil", "anthropic-api-key")
    assert res["granted"] is False
    assert res["value"] is None
    assert res["token"] is None
    log = (tmp_path / "audit.log").read_text()
    assert '"decision": "expired"' in log


async def test_add_policy_times_out_without_modifying_file(tmp_path):
    broker = _make_broker(tmp_path, _AUTO_POLICY)
    broker.config = dataclasses.replace(broker.config, escalation_timeout_seconds=0.01)
    before = open(broker.config.policies_path, "r", encoding="utf-8").read()
    res = await broker.add_policy(
        {"name": "new", "agent": "x", "credential": "y", "auto_approve": True}
    )
    assert res["added"] is False
    after = open(broker.config.policies_path, "r", encoding="utf-8").read()
    assert before == after
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_mcp_server.py -k "times_out" -v`
Expected: FAIL — without the wiring, the escalation awaits forever, so the test hangs until pytest's per-test handling or returns the wrong result. To avoid a hang during the RED step, confirm failure by reasoning + a short timeout: run `python -m pytest tests/test_mcp_server.py -k "times_out" -v --timeout=10` if `pytest-timeout` is available; otherwise observe the test does not pass (the calls currently never raise/return on timeout). Expected once wiring is absent: the test fails (hang or AssertionError).

- [ ] **Step 3: Add `import asyncio` to mcp_server.py**

In `broker/mcp_server.py`, add `import asyncio` to the stdlib import block (with `import datetime`, `import os`):

```python
import asyncio
import datetime
import os
```

- [ ] **Step 4: Wire the timeout into `_escalate`**

In `broker/mcp_server.py`, the `_escalate` method currently contains:

```python
        approved = await self.approvals.submit(agent, credential)
        if approved:
            return self._grant(agent, credential, mode, f"manual:{policy_name}")
```

Replace the `approved = await self.approvals.submit(agent, credential)` line with a timeout-aware call plus a timeout handler inserted immediately before the `if approved:` line:

```python
        try:
            approved = await self.approvals.submit(
                agent, credential, timeout=self.config.escalation_timeout_seconds or None
            )
        except asyncio.TimeoutError:
            self.audit.log(
                agent=agent,
                credential_requested=credential,
                policy_matched=policy_name,
                decision="expired",
                mode=mode,
                token_expiry=None,
            )
            return {
                "granted": False,
                "token": None,
                "token_expiry": None,
                "value": None,
                "reason": "escalation timed out",
            }
        if approved:
            return self._grant(agent, credential, mode, f"manual:{policy_name}")
```

(The pre-existing `decision="escalated"` audit entry earlier in `_escalate` and the existing operator-denied branch after this stay unchanged.)

- [ ] **Step 5: Wire the timeout into `add_policy`**

In `broker/mcp_server.py`, `add_policy` currently begins:

```python
    async def add_policy(self, policy: dict) -> dict:
        # Hard rule: policy mutation ALWAYS escalates, regardless of mode/policy.
        approved = await self.approvals.submit("SYSTEM", f"policy.add:{policy.get('name')}")
        if not approved:
            return {"added": False, "reason": "policy change denied by operator"}
```

Replace those lines with:

```python
    async def add_policy(self, policy: dict) -> dict:
        # Hard rule: policy mutation ALWAYS escalates, regardless of mode/policy.
        try:
            approved = await self.approvals.submit(
                "SYSTEM",
                f"policy.add:{policy.get('name')}",
                timeout=self.config.escalation_timeout_seconds or None,
            )
        except asyncio.TimeoutError:
            return {"added": False, "reason": "policy change escalation timed out"}
        if not approved:
            return {"added": False, "reason": "policy change denied by operator"}
```

(Everything after — the validate-before-write persistence — is unchanged.)

- [ ] **Step 6: Run the new tests to verify they pass**

Run: `python -m pytest tests/test_mcp_server.py -k "times_out" -v`
Expected: PASS (2 passed), each completing in well under a second.

- [ ] **Step 7: Update the README**

In `README.md`, in the configuration section/table, add a row/entry for `ESCALATION_TIMEOUT_SECONDS` describing: seconds to wait for operator approval before failing closed; `0` = disabled (wait forever), the default; set `> 0` for headless/unattended deployments.

In the README "Audit Log" section, update the `decision` line to list all four values: `approved`, `denied`, `escalated`, `expired` (add `expired` — "escalated request that timed out waiting for the operator and was auto-denied").

- [ ] **Step 8: Run the full suite**

Run: `python -m pytest -q`
Expected: all pass (now 49), pristine. Confirm no test hangs (all timeout tests use sub-second values).

- [ ] **Step 9: Commit**

```bash
git add broker/mcp_server.py README.md tests/test_mcp_server.py
git commit -m "feat: enforce escalation timeout in broker (fail closed) + docs"
```
(Append the Co-Authored-By trailer.)

---

## Self-Review

**Spec coverage:**
- §2 Config (`escalation_timeout_seconds`, env, default 0, `.env.example`, README) → Task 1 (field/env/.env.example) + Task 3 (README). ✓
- §3 Queue (`submit(timeout=)`, `wait_for`, remove + re-raise, `None` unchanged) → Task 2. ✓
- §4.1 `_escalate` (pass timeout, catch, audit `expired`, fail closed) → Task 3 Step 4. ✓
- §4.2 `add_policy` (pass timeout, catch, `added: False`, file untouched) → Task 3 Step 5 + test in Step 1. ✓
- §5 Audit (`"expired"` in `_VALID_DECISIONS`, README) → Task 1 Step 5 + Task 3 Step 7. ✓
- §6 Testing (queue timeout/resolve/None; broker credential timeout + policy.add timeout; config parse; audit expired) → Tasks 1–3 tests. ✓
- §7 Out of scope — nothing in the plan adds per-policy timeouts, retries, or agent retry signaling. ✓

**Placeholder scan:** Task 3 Step 1 initially shows a placeholder snippet but immediately replaces it with the concrete working test; the deliverable code is fully specified. Task 3 Step 2 (RED) notes the hang risk and gives a concrete way to observe failure (`--timeout` if available, else reasoning). All implementation steps contain complete code. No "TBD"/"add error handling"/etc.

**Type consistency:** `escalation_timeout_seconds` (int, → `or None` to float|None at the call), `submit(..., timeout: Optional[float] = None)`, `asyncio.TimeoutError`, `_remove(request)`, audit `decision="expired"`, and the `{granted, token, token_expiry, value, reason}` / `{added, reason}` dict shapes are consistent across tasks and match the existing code in `mcp_server.py`.

**Note (test ergonomics):** the broker timeout tests set `escalation_timeout_seconds=0.01` via `dataclasses.replace`. The field is typed `int`, but the value is only ever passed through to `asyncio.wait_for`, which accepts a float; nothing coerces or validates it as int at runtime, so a fractional value keeps the tests fast (sub-second) without a real 1s+ wait. This is test-only; production env parsing remains `int`.
