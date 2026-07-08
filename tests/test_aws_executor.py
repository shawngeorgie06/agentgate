from __future__ import annotations

import inspect

from broker.aws_executor import Boto3StsExecutor, StsExecutor


def test_protocol_method_signature():
    sig = inspect.signature(StsExecutor.assume_role)
    params = list(sig.parameters)
    assert params == [
        "self", "access_key_id", "secret_access_key", "role_arn",
        "session_name", "duration_seconds", "region", "external_id",
    ]


def test_boto3_executor_satisfies_protocol_without_importing_boto3():
    # Importing the module must NOT import boto3 (it is lazy). Constructing the
    # executor is also import-free; only calling assume_role would import boto3.
    import sys
    assert "boto3" not in sys.modules
    ex = Boto3StsExecutor()
    assert isinstance(ex, StsExecutor)


class _FakeSts:
    def __init__(self):
        self.calls = []

    async def assume_role(self, access_key_id, secret_access_key, *, role_arn,
                          session_name, duration_seconds, region, external_id):
        self.calls.append(dict(
            access_key_id=access_key_id, role_arn=role_arn, session_name=session_name,
            duration_seconds=duration_seconds, region=region, external_id=external_id,
        ))
        return {"access_key_id": "ASIA_FAKE", "secret_access_key": "s3cr3t",
                "session_token": "tok", "expiration": "2026-07-06T10:15:00+00:00"}


def test_fake_satisfies_protocol():
    assert isinstance(_FakeSts(), StsExecutor)
