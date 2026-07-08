from __future__ import annotations

from dataclasses import dataclass

from broker.encrypted_store import EncryptedStore


@dataclass(frozen=True)
class AwsResource:
    name: str
    role_arn: str
    region: str
    external_id: str | None
    created_at: str


class AwsResourceStore(EncryptedStore):
    """Registered AWS role resources. Nothing here is secret (the broker key
    lives in AwsKeyStore) — EncryptedStore base buys 0600 perms, atomic
    writes, and per-access disk re-read, not encryption."""

    _SECTION = "aws_resources"

    def store(self, resource: AwsResource) -> None:
        self._entries()[resource.name] = {
            "role_arn": resource.role_arn,
            "region": resource.region,
            "external_id": resource.external_id,
            "created_at": resource.created_at,
        }
        self._write(self._data)

    def get(self, name: str) -> AwsResource:
        entries = self._entries()
        if name not in entries:
            raise KeyError(name)
        rec = entries[name]
        return AwsResource(
            name=name,
            role_arn=rec["role_arn"],
            region=rec["region"],
            external_id=rec["external_id"],
            created_at=rec["created_at"],
        )

    def delete(self, name: str) -> None:
        entries = self._entries()
        if name not in entries:
            raise KeyError(name)
        del entries[name]
        self._write(self._data)

    def list_names(self) -> list[str]:
        return sorted(self._entries().keys())

    def list_metadata(self) -> list[dict]:
        return [
            {"name": name, **rec}
            for name, rec in sorted(self._entries().items())
        ]
