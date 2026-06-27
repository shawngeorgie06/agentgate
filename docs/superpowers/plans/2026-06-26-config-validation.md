# Config Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `Config.from_env` reject malformed or nonsensical env values with a clear, var-naming `ConfigError` (instead of a raw `ValueError` or silent acceptance), and surface it as a clean stderr message + non-zero exit in the broker and CLI entry points.

**Architecture:** Add a `ConfigError(ValueError)` and two small validation helpers (`_require_int`, `_require_non_empty`) to `broker/config.py`; route every field through them in `from_env`, failing fast on the first bad field. Then catch `ConfigError` in `broker/main.py:main()` and `cli/commands.py:run()` to print the message to stderr and exit non-zero.

**Tech Stack:** Python 3.11+, pytest (env injected as a plain mapping), existing AgentGate modules.

## Global Constraints

- Python 3.11+. No hardcoded paths — config comes from env via `Config`.
- Fail fast on the FIRST offending field (no error aggregation).
- `ConfigError` subclasses `ValueError` (backward compatible with callers expecting `ValueError`).
- Validation rules: `TOKEN_TTL_MINUTES` must parse as int AND be ≥ 1; `ESCALATION_TIMEOUT_SECONDS` must parse as int and KEEP the existing `max(0, …)` clamp (negative = disabled, only non-numeric raises); the four path vars (`POLICIES_PATH`, `STATE_PATH`, `LOGS_PATH`, `CREDENTIALS_PATH`) must be non-empty; `AGENTGATE_MASTER_PASSWORD` unchanged (optional).
- Every error message names the offending variable; value errors also include the offending value (e.g. `TOKEN_TTL_MINUTES must be a positive integer, got 'abc'`).
- This module set uses `from __future__ import annotations` + `typing.Optional` style — match it.
- Full suite must stay green and pristine (`python -m pytest -q`) before each commit. Run from repo root `C:\Users\georg\agentgate`; Python is `python`.
- Commit one per task on branch feature/agentgate-v1 (per the operator's confirmed approach for this build). Do not push or use `--no-verify`. End every commit message with a blank line then exactly:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`

---

## File Structure

| File | Change |
|------|--------|
| `broker/config.py` | Add `ConfigError`, `_require_int`, `_require_non_empty`; route `from_env` fields through them |
| `broker/main.py` | `main()` catches `ConfigError` → stderr + non-zero exit |
| `cli/commands.py` | `run()` catches `ConfigError` around `Config.from_env()` → stderr + non-zero return |
| `tests/test_config.py`, `tests/test_cli_commands.py` | Coverage |

Two tasks: (1) config validation + tests, (2) graceful surfacing + tests.

---

## Task 1: Config validation

**Files:**
- Modify: `broker/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Produces: `broker.config.ConfigError` (subclass of `ValueError`). `Config.from_env` raises `ConfigError` (naming the variable) when `TOKEN_TTL_MINUTES` is non-int or `< 1`, when `ESCALATION_TIMEOUT_SECONDS` is non-int, or when any of the four path vars is empty. `ESCALATION_TIMEOUT_SECONDS` negatives still clamp to `0`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_config.py`:

```python
import pytest
from broker.config import Config, ConfigError


def test_config_error_is_a_valueerror():
    assert issubclass(ConfigError, ValueError)


def test_token_ttl_non_numeric_raises_naming_the_var():
    with pytest.raises(ConfigError) as exc:
        Config.from_env({"TOKEN_TTL_MINUTES": "abc"})
    assert "TOKEN_TTL_MINUTES" in str(exc.value)
    assert "abc" in str(exc.value)


def test_token_ttl_zero_raises():
    with pytest.raises(ConfigError):
        Config.from_env({"TOKEN_TTL_MINUTES": "0"})


def test_token_ttl_negative_raises():
    with pytest.raises(ConfigError):
        Config.from_env({"TOKEN_TTL_MINUTES": "-1"})


def test_token_ttl_valid_passes():
    assert Config.from_env({"TOKEN_TTL_MINUTES": "30"}).token_ttl_minutes == 30


def test_escalation_non_numeric_raises_naming_the_var():
    with pytest.raises(ConfigError) as exc:
        Config.from_env({"ESCALATION_TIMEOUT_SECONDS": "soon"})
    assert "ESCALATION_TIMEOUT_SECONDS" in str(exc.value)


def test_escalation_negative_still_clamps_to_zero():
    assert Config.from_env({"ESCALATION_TIMEOUT_SECONDS": "-5"}).escalation_timeout_seconds == 0


def test_empty_path_raises_naming_the_var():
    with pytest.raises(ConfigError) as exc:
        Config.from_env({"STATE_PATH": ""})
    assert "STATE_PATH" in str(exc.value)


def test_defaults_are_all_valid():
    cfg = Config.from_env({})
    assert cfg.token_ttl_minutes == 60
    assert cfg.escalation_timeout_seconds == 0
    assert cfg.state_path  # non-empty
```

(Reuse any existing `Config` import at the top of the file rather than duplicating; ensure `ConfigError` and `pytest` are imported.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_config.py -k "config_error or token_ttl or escalation or empty_path or defaults_are" -v`
Expected: FAIL — `ImportError: cannot import name 'ConfigError'` (and, once that's added, assertion failures until validation exists).

- [ ] **Step 3: Add `ConfigError` and the helpers to `broker/config.py`**

After the imports and before `_DEFAULTS` (or directly after `_DEFAULTS` — keep it above `Config`), add:

```python
class ConfigError(ValueError):
    """Raised when an environment value is missing, malformed, or out of range."""


def _require_int(value: str, var: str, minimum: Optional[int] = None) -> int:
    positive = minimum is not None and minimum > 0
    kind = "a positive integer" if positive else "an integer"
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ConfigError(f"{var} must be {kind}, got {value!r}") from None
    if minimum is not None and n < minimum:
        kind = "a positive integer" if positive else f">= {minimum}"
        raise ConfigError(f"{var} must be {kind}, got {value!r}")
    return n


def _require_non_empty(value: str, var: str) -> str:
    if not value:
        raise ConfigError(f"{var} must not be empty")
    return value
```

- [ ] **Step 4: Route `from_env` fields through the helpers**

In `broker/config.py`, replace the `return cls(...)` block in `from_env` (currently lines ~34-42) with:

```python
        return cls(
            policies_path=_require_non_empty(get("POLICIES_PATH"), "POLICIES_PATH"),
            state_path=_require_non_empty(get("STATE_PATH"), "STATE_PATH"),
            logs_path=_require_non_empty(get("LOGS_PATH"), "LOGS_PATH"),
            credentials_path=_require_non_empty(get("CREDENTIALS_PATH"), "CREDENTIALS_PATH"),
            token_ttl_minutes=_require_int(get("TOKEN_TTL_MINUTES"), "TOKEN_TTL_MINUTES", minimum=1),
            escalation_timeout_seconds=max(
                0, _require_int(get("ESCALATION_TIMEOUT_SECONDS"), "ESCALATION_TIMEOUT_SECONDS")
            ),
            master_password=env.get("AGENTGATE_MASTER_PASSWORD"),
        )
```

(The `get`, `env`, and `_DEFAULTS` logic above this block is unchanged. `Optional` is already imported.)

- [ ] **Step 5: Run the new tests to verify they pass**

Run: `python -m pytest tests/test_config.py -v`
Expected: PASS (all config tests, including the new ones and the pre-existing escalation/default tests).

- [ ] **Step 6: Run the full suite**

Run: `python -m pytest -q`
Expected: all pass (was 51; now 60), pristine — no warnings. Confirm no existing test broke (existing tests construct `Config.from_env` with valid values/defaults, so they remain green).

- [ ] **Step 7: Commit**

```bash
git add broker/config.py tests/test_config.py
git commit -m "feat: validate config env values with ConfigError (fail fast)"
```
(Append the Co-Authored-By trailer per Global Constraints.)

---

## Task 2: Graceful surfacing in entry points

**Files:**
- Modify: `broker/main.py` (`main()`)
- Modify: `cli/commands.py` (`run()`)
- Test: `tests/test_cli_commands.py`

**Interfaces:**
- Consumes: `broker.config.ConfigError` (Task 1).
- Produces: `broker/main.py:main()` catches `ConfigError`, prints it to stderr, and exits non-zero. `cli/commands.py:run()` catches `ConfigError` from `Config.from_env()`, prints to stderr, and returns a non-zero exit code (does not raise).

- [ ] **Step 1: Write the failing CLI test**

Add to `tests/test_cli_commands.py`:

```python
def test_cli_returns_nonzero_on_invalid_config(monkeypatch, capsys):
    # No injected config -> run() calls Config.from_env(), which reads os.environ.
    monkeypatch.setenv("TOKEN_TTL_MINUTES", "abc")
    rc = commands.run(["status"])  # config=None on purpose
    assert rc != 0
    err = capsys.readouterr().err
    assert "TOKEN_TTL_MINUTES" in err
```

(Reuse the existing `from cli import commands` import at the top of the file.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/test_cli_commands.py -k invalid_config -v`
Expected: FAIL — currently `Config.from_env()` raises `ConfigError` which propagates out of `run()` (an exception, not a non-zero return), so the test errors instead of asserting cleanly.

- [ ] **Step 3: Catch `ConfigError` in `cli/commands.py:run()`**

In `cli/commands.py`, add the import (with the other `from broker...` imports near the top):

```python
from broker.config import Config, ConfigError
```

(If `Config` is already imported on its own line, change that line to the combined import above rather than adding a duplicate.)

Then change the first line of `run()` from:

```python
    config = config or Config.from_env()
```

to:

```python
    if config is None:
        try:
            config = Config.from_env()
        except ConfigError as exc:
            print(f"[AgentGate] configuration error: {exc}", file=sys.stderr)
            return 2
```

(`sys` is already imported in `cli/commands.py`.)

- [ ] **Step 4: Run the CLI test to verify it passes**

Run: `python -m pytest tests/test_cli_commands.py -k invalid_config -v`
Expected: PASS — `run(["status"])` returns `2` and stderr contains `TOKEN_TTL_MINUTES`.

- [ ] **Step 5: Catch `ConfigError` in `broker/main.py:main()`**

In `broker/main.py`, add the import (with the other `from broker...` imports near the top):

```python
from broker.config import Config, ConfigError
```

(If `Config` is already imported on its own line, change that line to the combined import rather than adding a duplicate.)

Then change `main()` from:

```python
def main() -> None:
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\n[AgentGate] interrupted", file=sys.stderr)
```

to:

```python
def main() -> None:
    try:
        asyncio.run(run())
    except ConfigError as exc:
        print(f"[AgentGate] configuration error: {exc}", file=sys.stderr)
        raise SystemExit(2)
    except KeyboardInterrupt:
        print("\n[AgentGate] interrupted", file=sys.stderr)
```

(`sys` is already imported in `broker/main.py`.)

- [ ] **Step 6: Run the full suite**

Run: `python -m pytest -q`
Expected: all pass (was 60; now 61), pristine. The broker `main()` ConfigError path is covered indirectly (same `Config.from_env` validation, exercised directly in Task 1 and via the CLI test here); no async server is started in tests.

- [ ] **Step 7: Commit**

```bash
git add broker/main.py cli/commands.py tests/test_cli_commands.py
git commit -m "feat: surface ConfigError as clean stderr message + non-zero exit"
```
(Append the Co-Authored-By trailer.)

---

## Self-Review

**Spec coverage:**
- §2 `ConfigError(ValueError)` → Task 1 Step 3 + `test_config_error_is_a_valueerror`. ✓
- §3 rules: `TOKEN_TTL_MINUTES` int & ≥1 → Task 1 (`_require_int(..., minimum=1)`) + tests (non-numeric/0/-1/valid); `ESCALATION_TIMEOUT_SECONDS` int + clamp preserved → Task 1 (`max(0, _require_int(...))`) + tests (non-numeric raises, -5 clamps to 0); non-empty paths → Task 1 (`_require_non_empty`) + empty-path test; master_password unchanged → not routed through helpers. ✓
- §4 messages name var (+ value for value errors) → helper messages + assertions on `"TOKEN_TTL_MINUTES"`/`"abc"`/`"STATE_PATH"`. ✓
- §5 graceful surfacing in main.py + cli → Task 2. ✓
- §6 testing (config matrix + cli catches ConfigError nonzero) → Tasks 1 & 2 tests. ✓
- §7 out of scope — plan adds no error aggregation, no policy-content validation, no master-password change. ✓

**Placeholder scan:** every code step contains complete code; no "TBD"/"add validation"/etc. Test bodies are concrete with explicit assertions.

**Type consistency:** `ConfigError`, `_require_int(value, var, minimum=None) -> int`, `_require_non_empty(value, var) -> str`, and the `from_env` field wiring match between Task 1's definition and Task 2's usage. Exit codes: CLI `run()` returns `2`, `main()` raises `SystemExit(2)` — consistent. Both entry points print `"[AgentGate] configuration error: {exc}"` to stderr.

**Note (test counts):** projected totals (60 after Task 1, 61 after Task 2) assume the current suite is 51 and Task 1 adds 9 tests, Task 2 adds 1. The implementer should treat "all green + pristine" as the gate, not the exact number, since incidental test counts may drift.
