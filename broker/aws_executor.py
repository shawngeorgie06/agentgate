from __future__ import annotations

import asyncio
import datetime
from typing import Protocol, runtime_checkable


@runtime_checkable
class StsExecutor(Protocol):
    async def assume_role(
        self,
        access_key_id: str,
        secret_access_key: str,
        *,
        role_arn: str,
        session_name: str,
        duration_seconds: int,
        region: str,
        external_id: str | None,
    ) -> dict:
        ...


class Boto3StsExecutor:
    """Real STS caller. boto3 is imported lazily inside assume_role so the
    broker runs (and the whole unit-test suite imports) without boto3 present;
    a missing boto3 surfaces as an exception the grant path turns into a
    generic audited deny. The client is built with EXPLICIT keys only — never
    the ambient credential chain."""

    async def assume_role(
        self,
        access_key_id: str,
        secret_access_key: str,
        *,
        role_arn: str,
        session_name: str,
        duration_seconds: int,
        region: str,
        external_id: str | None,
    ) -> dict:
        return await asyncio.to_thread(
            self._assume_role_sync,
            access_key_id, secret_access_key, role_arn, session_name,
            duration_seconds, region, external_id,
        )

    @staticmethod
    def _assume_role_sync(
        access_key_id, secret_access_key, role_arn, session_name,
        duration_seconds, region, external_id,
    ) -> dict:
        import boto3  # lazy: keeps import-time (and tests) boto3-free

        client = boto3.client(
            "sts",
            region_name=region,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
        )
        kwargs = dict(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            DurationSeconds=duration_seconds,
        )
        if external_id is not None:
            kwargs["ExternalId"] = external_id
        resp = client.assume_role(**kwargs)
        creds = resp["Credentials"]
        expiration = creds["Expiration"]
        if isinstance(expiration, datetime.datetime):
            expiration = expiration.astimezone(datetime.timezone.utc).isoformat(
                timespec="seconds"
            )
        return {
            "access_key_id": creds["AccessKeyId"],
            "secret_access_key": creds["SecretAccessKey"],
            "session_token": creds["SessionToken"],
            "expiration": expiration,
        }
