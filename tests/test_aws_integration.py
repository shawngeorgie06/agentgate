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
