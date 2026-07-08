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
