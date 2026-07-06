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
