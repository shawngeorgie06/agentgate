from __future__ import annotations

from dataclasses import dataclass

from broker import crypto
from broker.encrypted_store import EncryptedStore


@dataclass(frozen=True)
class Connection:
    provider: str
    client_id: str
    client_secret: str
    refresh_token: str
    scopes: list[str]
    created_at: str


class ConnectionStore(EncryptedStore):
    _SECTION = "connections"

    def store(self, name: str, conn: Connection) -> None:
        self._entries()[name] = {
            "provider": conn.provider,
            "client_id": conn.client_id,
            "client_secret": crypto.encrypt(self._key, conn.client_secret),
            "refresh_token": crypto.encrypt(self._key, conn.refresh_token),
            "scopes": list(conn.scopes),
            "created_at": conn.created_at,
        }
        self._write(self._data)

    def get(self, name: str) -> Connection:
        entries = self._entries()
        if name not in entries:
            raise KeyError(name)
        rec = entries[name]
        return Connection(
            provider=rec["provider"],
            client_id=rec["client_id"],
            client_secret=crypto.decrypt(self._key, rec["client_secret"]),
            refresh_token=crypto.decrypt(self._key, rec["refresh_token"]),
            scopes=list(rec["scopes"]),
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
            {
                "name": name,
                "provider": rec["provider"],
                "scopes": list(rec["scopes"]),
                "created_at": rec["created_at"],
            }
            for name, rec in sorted(self._entries().items())
        ]
