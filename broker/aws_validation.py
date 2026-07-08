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
