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


def test_glob_patterns_match_agent_and_credential(tmp_path):
    path = _write(tmp_path, """
        policies:
          - name: all-claudes-aws
            agent: "claude-*"
            credential: "aws-*"
            auto_approve: true
          - name: default-deny
            agent: "*"
            credential: "*"
            auto_approve: false
            escalate: true
    """)
    eng = PolicyEngine.from_file(path)
    assert eng.evaluate("claude-code", "aws-access-key").policy_name == "all-claudes-aws"
    assert eng.evaluate("claude-code-2", "aws-secret-key").policy_name == "all-claudes-aws"
    assert eng.evaluate("codex", "aws-access-key").policy_name == "default-deny"
    assert eng.evaluate("claude-code", "anthropic-api-key").policy_name == "default-deny"


def test_lint_flags_policy_shadowed_by_earlier_catch_all(tmp_path):
    path = _write(tmp_path, """
        policies:
          - name: catch-all-first
            agent: "*"
            credential: "*"
            auto_approve: false
            escalate: true
          - name: never-reached
            agent: claude-code
            credential: k
            auto_approve: true
    """)
    warnings = PolicyEngine.lint_file(path)
    assert len(warnings) == 1
    assert "never-reached" in warnings[0] and "catch-all-first" in warnings[0]


def test_lint_clean_for_conventional_layout(tmp_path):
    # Specific policies first, default-deny last: nothing shadowed.
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
    assert PolicyEngine.lint_file(path) == []


def test_lint_time_windowed_policy_does_not_shadow(tmp_path):
    # A time-windowed match is not always-on; later policies still fire
    # outside the window.
    path = _write(tmp_path, """
        policies:
          - name: daytime
            agent: claude-code
            credential: k
            auto_approve: true
            time_window: {start: "09:00", end: "17:00"}
          - name: nights
            agent: claude-code
            credential: k
            auto_approve: false
            escalate: true
    """)
    assert PolicyEngine.lint_file(path) == []


def test_validate_file_rejects_non_string_time_without_raising(tmp_path):
    p = tmp_path / "policies.yaml"
    p.write_text(
        "policies:\n"
        "  - name: bad-time\n"
        "    agent: a\n"
        "    credential: k\n"
        "    auto_approve: true\n"
        "    time_window: {start: 900, end: 1700}\n"
    )
    errors = PolicyEngine.validate_file(str(p))  # must not raise
    assert errors  # non-empty: the malformed time_window is reported
