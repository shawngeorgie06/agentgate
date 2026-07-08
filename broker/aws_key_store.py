from __future__ import annotations

from dataclasses import dataclass, field

from broker import crypto
from broker.encrypted_store import EncryptedStore


@dataclass(frozen=True)
class AwsBrokerKey:
    access_key_id: str
    secret_access_key: str = field(repr=False)


class AwsKeyStore(EncryptedStore):
    """The broker's dedicated IAM access key. Secret encrypted at rest; the
    access key id is stored readable. Overwriting is allowed — rotating this
    key is routine operator maintenance."""

    _SECTION = "aws_key"
    _KEY = "broker"

    def set(self, access_key_id: str, secret_access_key: str) -> None:
        self._entries()[self._KEY] = {
            "access_key_id": access_key_id,
            "secret_access_key": crypto.encrypt(self._key, secret_access_key),
        }
        self._write(self._data)

    def is_set(self) -> bool:
        return self._KEY in self._entries()

    def load(self) -> AwsBrokerKey:
        entries = self._entries()
        if self._KEY not in entries:
            raise KeyError("aws broker key not set")
        rec = entries[self._KEY]
        return AwsBrokerKey(
            access_key_id=rec["access_key_id"],
            secret_access_key=crypto.decrypt(self._key, rec["secret_access_key"]),
        )
