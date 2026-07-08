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
