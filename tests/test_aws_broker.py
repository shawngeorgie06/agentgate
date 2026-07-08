from __future__ import annotations

import pytest

from broker import aws_broker
from broker.aws_broker import AwsCred, build_session_name
from broker.aws_validation import AwsValidationError


class _Key:
    access_key_id = "AKIA_BROKER"
    secret_access_key = "broker-secret"


class _Res:
    def __init__(self, external_id=None):
        self.name = "s3-reader"
        self.role_arn = "arn:aws:iam::123456789012:role/agent-s3-reader"
        self.region = "us-east-1"
        self.external_id = external_id


class _FakeSts:
    def __init__(self, expiration="2026-07-06T10:15:00+00:00"):
        self.calls = []
        self._expiration = expiration

    async def assume_role(self, access_key_id, secret_access_key, *, role_arn,
                          session_name, duration_seconds, region, external_id):
        self.calls.append(dict(
            access_key_id=access_key_id, secret_access_key=secret_access_key,
            role_arn=role_arn, session_name=session_name,
            duration_seconds=duration_seconds, region=region, external_id=external_id,
        ))
        return {"access_key_id": "ASIA_TEMP", "secret_access_key": "temp-secret",
                "session_token": "temp-token", "expiration": self._expiration}


def test_build_session_name_composes():
    assert build_session_name("claude-code", "s3-reader") == "agentgate-claude-code-s3-reader"


def test_build_session_name_truncates_to_64():
    name = build_session_name("a" * 40, "b" * 40)
    assert len(name) == 64
    assert name.startswith("agentgate-")


def test_build_session_name_rejects_unsafe_after_truncation():
    with pytest.raises(AwsValidationError):
        build_session_name("bad agent", "s3")  # space is outside the STS charset


async def test_assume_role_passes_exact_params_without_external_id():
    ex = _FakeSts()
    cred = await aws_broker.assume_role(
        ex, _Key(), _Res(), ttl_minutes=15, session_name="agentgate-cc-s3",
    )
    assert isinstance(cred, AwsCred)
    assert cred.access_key_id == "ASIA_TEMP"
    assert cred.secret_access_key == "temp-secret"
    assert cred.session_token == "temp-token"
    assert cred.expiration == "2026-07-06T10:15:00+00:00"
    assert cred.region == "us-east-1"
    (call,) = ex.calls
    assert call["access_key_id"] == "AKIA_BROKER"
    assert call["secret_access_key"] == "broker-secret"
    assert call["role_arn"] == "arn:aws:iam::123456789012:role/agent-s3-reader"
    assert call["session_name"] == "agentgate-cc-s3"
    assert call["duration_seconds"] == 15 * 60
    assert call["region"] == "us-east-1"
    assert call["external_id"] is None


async def test_assume_role_forwards_external_id_when_set():
    ex = _FakeSts()
    await aws_broker.assume_role(
        ex, _Key(), _Res(external_id="ext-42"), ttl_minutes=30,
        session_name="agentgate-cc-s3",
    )
    assert ex.calls[0]["external_id"] == "ext-42"
    assert ex.calls[0]["duration_seconds"] == 30 * 60


async def test_assume_role_revalidates_resource_at_the_sink():
    ex = _FakeSts()
    bad = _Res()
    bad.role_arn = "arn:aws:iam::123:role/x"  # bad account id
    with pytest.raises(AwsValidationError):
        await aws_broker.assume_role(ex, _Key(), bad, ttl_minutes=15,
                                     session_name="agentgate-cc-s3")
    assert ex.calls == []  # never called STS with an unvalidated ARN


def test_awscred_secret_fields_not_in_repr():
    cred = AwsCred(access_key_id="ASIA", secret_access_key="SECRET_VALUE",
                   session_token="TOKEN_VALUE", expiration="2026-07-06T10:15:00+00:00",
                   region="us-east-1")
    r = repr(cred)
    assert "SECRET_VALUE" not in r and "TOKEN_VALUE" not in r
