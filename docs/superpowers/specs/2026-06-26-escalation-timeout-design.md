# Escalation Timeout — Design Spec

**Date:** 2026-06-26
**Status:** Approved (design), pending implementation plan
**One-liner:** Bound how long an escalated credential/policy request waits for operator approval, so headless deployments fail closed instead of hanging forever. Opt-in; zero behavior change when unset.

---

## 1. Problem & Goal

Today, `Broker._escalate` and `Broker.add_policy` call `await ApprovalQueue.submit(...)`, which awaits an `asyncio.Future` with no timeout. The future is only ever resolved by the interactive CLI loop (`broker/main.py`). In any deployment where the MCP server runs without that interactive CLI consuming approvals (e.g. the headless/AWS-ECS story the README markets toward), an escalated `credential.request` — or a `policy.add` — hangs forever.

**Goal:** add an optional, configurable timeout that bounds the wait. When it fires, the request **fails closed** (deny — never grant on no-answer). When unset, behavior is exactly as today (wait indefinitely), so existing interactive use is unaffected.

---

## 2. Configuration

`broker/config.py` gains one field, following the existing `TOKEN_TTL_MINUTES` pattern:

- `escalation_timeout_seconds: int`
- Env var: `ESCALATION_TIMEOUT_SECONDS`
- Default: `"0"` (in `_DEFAULTS`)
- Semantics: `0` (or unset) = **disabled** = wait forever. Any value `> 0` = bound the wait to that many seconds.

Also added to:
- `.env.example` — with a comment explaining `0` = disabled.
- `README.md` — the configuration table/section.

The broker converts the int to the queue's `timeout` argument as `self.config.escalation_timeout_seconds or None` (so `0` maps to `None` = no timeout).

---

## 3. Queue behavior (`broker/approval.py`)

`ApprovalQueue.submit` gains an optional keyword:

```python
async def submit(self, agent: str, credential: str, timeout: float | None = None) -> bool:
```

- `timeout is None` → `return await req.future` (unchanged from today).
- `timeout` set → `await asyncio.wait_for(req.future, timeout)`. On `asyncio.TimeoutError`:
  1. Remove the request from the internal queue (so it does not linger as a phantom pending item).
  2. Re-raise `asyncio.TimeoutError`.

Raising (rather than returning `False`) is deliberate: it lets the caller distinguish a **timeout** from an **explicit operator denial** (which returns `False`), which the audit layer needs.

Notes:
- `asyncio.wait_for` cancels the underlying future on timeout; a later `resolve()` on that request is a no-op because `future.done()` is true and the request was already removed (the existing `resolve` already guards both with `if not future.done()` and a `try/except ValueError` on removal).
- `get_pending()` / `pending_count()` already skip `done()` futures, so a cancelled-and-removed request is correctly excluded.

---

## 4. Broker behavior (`broker/mcp_server.py`)

Both escalation paths pass the configured timeout and catch `asyncio.TimeoutError`. The timeout applies **uniformly** to credential requests and policy mutations — both fail closed.

### 4.1 `_escalate` (credential requests)

```python
try:
    approved = await self.approvals.submit(
        agent, credential, timeout=self.config.escalation_timeout_seconds or None
    )
except asyncio.TimeoutError:
    self.audit.log(
        agent=agent, credential_requested=credential, policy_matched=policy_name,
        decision="expired", mode=mode, token_expiry=None,
    )
    return {"granted": False, "token": None, "token_expiry": None,
            "value": None, "reason": "escalation timed out"}
# ... existing approved / denied handling unchanged ...
```

The pre-await `decision="escalated"` audit entry is still written (the request *was* escalated); the timeout adds a terminal `decision="expired"` entry. **Fail closed:** no token issued, no value returned.

### 4.2 `add_policy`

```python
try:
    approved = await self.approvals.submit(
        "SYSTEM", f"policy.add:{policy.get('name')}",
        timeout=self.config.escalation_timeout_seconds or None,
    )
except asyncio.TimeoutError:
    return {"added": False, "reason": "policy change escalation timed out"}
if not approved:
    return {"added": False, "reason": "policy change denied by operator"}
# ... existing validate-before-write path unchanged ...
```

Because the policy file is only written **after** an explicit approval, a timeout can never mutate `policies.yaml`. The hard rule ("an agent can never autonomously change its own governing policy") therefore holds headless: an unattended `policy.add` is denied, never auto-applied.

---

## 5. Audit (`broker/audit.py`)

Add `"expired"` to `_VALID_DECISIONS`:

```python
_VALID_DECISIONS = {"approved", "denied", "escalated", "expired"}
```

A timed-out request is then distinguishable from an operator's explicit `"denied"` in `logs/audit.log`. The README audit-log section is updated to list `expired` among the decision values.

---

## 6. Testing

**`tests/test_approval.py`:**
- `submit` with a tiny timeout (e.g. `0.01`) that is never resolved → raises `asyncio.TimeoutError`, and `pending_count()` returns to `0` (request removed).
- `submit` with a timeout but resolved in time → returns the resolved value (`True`/`False`); no exception.
- `submit` with `timeout=None` → still awaits (existing tests remain green).

**`tests/test_mcp_server.py`:**
- Credential escalation with `ESCALATION_TIMEOUT_SECONDS` small and no operator → result `{granted: False, value: None}` and an audit entry with `decision="expired"`.
- `add_policy` with the timeout and no operator → `{added: False, ...}` and `policies.yaml` is byte-for-byte unchanged.
- (Existing escalation tests, which resolve the approval promptly, remain green.)

**`tests/test_config.py`:**
- `ESCALATION_TIMEOUT_SECONDS` parsed to int; default `0` when unset.

**`tests/test_audit.py`:**
- `decision="expired"` is accepted (no `ValueError`).

---

## 7. Out of scope (YAGNI)

Per-policy timeouts, retry/re-queue semantics, agent-facing "retry later" signaling, and any push notification to the operator. This spec delivers exactly one global, opt-in, fail-closed timeout.
