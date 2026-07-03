from __future__ import annotations

from dataclasses import dataclass

from broker import crypto
from broker.encrypted_store import EncryptedStore


@dataclass(frozen=True)
class DbResource:
    name: str
    host: str
    port: int
    dbname: str
    admin_user: str
    admin_password: str
    grants: list[dict]
    created_at: str


class DbResourceStore(EncryptedStore):
    _SECTION = "db_resources"

    def store(self, resource: DbResource) -> None:
        self._entries()[resource.name] = {
            "host": resource.host,
            "port": resource.port,
            "dbname": resource.dbname,
            "admin_user": resource.admin_user,
            "admin_password": crypto.encrypt(self._key, resource.admin_password),
            "grants": [dict(g) for g in resource.grants],
            "created_at": resource.created_at,
        }
        self._write(self._data)

    def get(self, name: str) -> DbResource:
        entries = self._entries()
        if name not in entries:
            raise KeyError(name)
        rec = entries[name]
        return DbResource(
            name=name,
            host=rec["host"],
            port=rec["port"],
            dbname=rec["dbname"],
            admin_user=rec["admin_user"],
            admin_password=crypto.decrypt(self._key, rec["admin_password"]),
            grants=[dict(g) for g in rec["grants"]],
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
                "host": rec["host"],
                "port": rec["port"],
                "dbname": rec["dbname"],
                "grants": [dict(g) for g in rec["grants"]],
                "created_at": rec["created_at"],
            }
            for name, rec in sorted(self._entries().items())
        ]
