# Config Validation — Design Spec

**Date:** 2026-06-26
**Status:** Approved (design), pending implementation plan
**One-liner:** `Config.from_env` rejects malformed or nonsensical environment values with a clear, actionable `ConfigError` instead of a raw `ValueError` (or silently accepting a bad value), so the broker never starts on a misconfiguration.

---

## 1. Problem & Goal

`broker/config.py`'s `Config.from_env` parses two integer env vars with bare `int(...)`:

```python
token_ttl_minutes=int(get("TOKEN_TTL_MINUTES")),
escalation_timeout_seconds=max(0, int(get("ESCALATION_TIMEOUT_SECONDS"))),
```

A non-numeric value (a typo in `.env`, e.g. `TOKEN_TTL_MINUTES=abc`) raises a raw `ValueError: invalid literal for int() with base 10: 'abc'` that names neither the variable nor the broker context, and aborts startup with a traceback. Values that *parse* but are nonsensical (e.g. `TOKEN_TTL_MINUTES=0`, which issues already-expired tokens) slip through silently. Paths set to an empty string also slip through.

The security review of the escalation-timeout feature flagged this as a project-wide config-validation gap.

**Goal:** validate env values at construction time and **fail fast** with a clear message that names the offending variable and value, so a misconfigured broker refuses to start with an actionable error rather than a traceback or silent bad behavior.

---

## 2. Error type

Add to `broker/config.py`:

```python
class ConfigError(ValueError):
    """Raised when an environment value is missing, malformed, or out of range."""
```

Subclassing `ValueError` keeps backward compatibility with any caller that already catches `ValueError`, while letting callers catch `ConfigError` specifically.

---

## 3. Validation rules

Applied inside `Config.from_env`, **failing fast on the first offending field** (raising immediately; no error aggregation):

| Env var | Rule | On violation |
|---------|------|--------------|
| `TOKEN_TTL_MINUTES` | parses as int **and** ≥ 1 | `ConfigError` |
| `ESCALATION_TIMEOUT_SECONDS` | parses as int (negative still clamps to `0` = disabled) | `ConfigError` only if non-numeric |
| `POLICIES_PATH` | non-empty string | `ConfigError` |
| `STATE_PATH` | non-empty string | `ConfigError` |
| `LOGS_PATH` | non-empty string | `ConfigError` |
| `CREDENTIALS_PATH` | non-empty string | `ConfigError` |
| `AGENTGATE_MASTER_PASSWORD` | unchanged — optional, `None` = prompt | — |

Rationale:
- `TOKEN_TTL_MINUTES` ≥ 1: a TTL of `0` or negative issues a token that is expired the moment it's granted — never valid.
- `ESCALATION_TIMEOUT_SECONDS`: the existing `max(0, ...)` clamp (non-positive = disabled = wait forever) is intentional and preserved; only a value that can't be parsed as an integer is an error.
- Paths: an empty path is always a misconfiguration; it would otherwise produce confusing downstream filesystem errors.

---

## 4. Messages

Messages name the variable and the offending value so the operator can fix `.env` directly:

- `TOKEN_TTL_MINUTES must be a positive integer, got 'abc'`
- `TOKEN_TTL_MINUTES must be a positive integer, got '0'`
- `ESCALATION_TIMEOUT_SECONDS must be an integer, got 'soon'`
- `STATE_PATH must not be empty`

Two small private helpers keep this DRY:

```python
def _require_int(value: str, var: str, minimum: int | None = None) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ConfigError(f"{var} must be {'a positive integer' if minimum and minimum > 0 else 'an integer'}, got {value!r}")
    if minimum is not None and n < minimum:
        raise ConfigError(f"{var} must be {'a positive integer' if minimum > 0 else f'>= {minimum}'}, got {value!r}")
    return n


def _require_non_empty(value: str, var: str) -> str:
    if not value:
        raise ConfigError(f"{var} must not be empty")
    return value
```

`from_env` then becomes (illustrative):

```python
return cls(
    policies_path=_require_non_empty(get("POLICIES_PATH"), "POLICIES_PATH"),
    state_path=_require_non_empty(get("STATE_PATH"), "STATE_PATH"),
    logs_path=_require_non_empty(get("LOGS_PATH"), "LOGS_PATH"),
    credentials_path=_require_non_empty(get("CREDENTIALS_PATH"), "CREDENTIALS_PATH"),
    token_ttl_minutes=_require_int(get("TOKEN_TTL_MINUTES"), "TOKEN_TTL_MINUTES", minimum=1),
    escalation_timeout_seconds=max(0, _require_int(get("ESCALATION_TIMEOUT_SECONDS"), "ESCALATION_TIMEOUT_SECONDS")),
    master_password=env.get("AGENTGATE_MASTER_PASSWORD"),
)
```

(The `_require_int`/`_require_non_empty` message wording is finalized in the plan; the requirement is only that each message names the variable and, for value errors, includes the offending value.)

---

## 5. Graceful surfacing (light touch)

So operators see the message rather than a traceback:

- `broker/main.py`'s `main()` catches `ConfigError`, prints the message to `stderr`, and exits with a non-zero code.
- `cli/commands.py`'s entry (where `Config.from_env()` is called when no `config` is injected) catches `ConfigError`, prints to `stderr`, and returns a non-zero exit code.

These are thin handlers; the validation logic lives only in `config.py`.

---

## 6. Testing

**`tests/test_config.py`** (env injected as a plain mapping — no real environment needed):
- `TOKEN_TTL_MINUTES`: non-numeric → `ConfigError` whose message contains `"TOKEN_TTL_MINUTES"`; `"0"` → `ConfigError`; `"-1"` → `ConfigError`; `"30"` → `30`; default (unset) → `60`.
- `ESCALATION_TIMEOUT_SECONDS`: non-numeric → `ConfigError`; `"-5"` → clamped to `0` (no raise); `"30"` → `30`; default → `0`.
- Paths: `STATE_PATH=""` → `ConfigError` naming `STATE_PATH`; defaults all valid and non-empty.
- `ConfigError` is a subclass of `ValueError` (so `pytest.raises(ValueError)` also catches it).

**`tests/test_cli_commands.py`** (or `tests/test_config.py`): a focused test that the CLI entry catches `ConfigError` and returns a non-zero exit code when an invalid value is present (via `monkeypatch.setenv("TOKEN_TTL_MINUTES", "abc")` and calling the CLI with no injected config).

---

## 7. Out of scope (YAGNI)

- Aggregating all config errors into one report (fail fast on the first offending field is sufficient and simpler).
- Validating policy *file contents* — that is `policy_engine`'s responsibility, already covered.
- Any change to the master-password resolution flow.
- A general schema/validation library — two helpers cover every field.
