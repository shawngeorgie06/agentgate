from __future__ import annotations

import json
import os
from dataclasses import dataclass

from broker import crypto


@dataclass(frozen=True)
class Connection:
    provider: str
    client_id: str
    client_secret: str
    refresh_token: str
    scopes: list[str]
    created_at: str


class ConnectionStore:
    def __init__(self, path: str, master_password: str) -> None:
        self._path = path
        is_new = not os.path.exists(self._path)
        self._data = self._load()
        self._key = crypto.derive_key(master_password, self._data["salt"])
        if is_new:
            self._write(self._data)

    def _load(self) -> dict:
        if os.path.exists(self._path):
            with open(self._path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        return {"salt": crypto.new_salt(), "connections": {}}

    def _write(self, data: dict) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self._path)), exist_ok=True)
        tmp = f"{self._path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, self._path)

    def store(self, name: str, conn: Connection) -> None:
        self._data["connections"][name] = {
            "provider": conn.provider,
            "client_id": conn.client_id,
            "client_secret": crypto.encrypt(self._key, conn.client_secret),
            "refresh_token": crypto.encrypt(self._key, conn.refresh_token),
            "scopes": list(conn.scopes),
            "created_at": conn.created_at,
        }
        self._write(self._data)

    def get(self, name: str) -> Connection:
        if name not in self._data["connections"]:
            raise KeyError(name)
        rec = self._data["connections"][name]
        return Connection(
            provider=rec["provider"],
            client_id=rec["client_id"],
            client_secret=crypto.decrypt(self._key, rec["client_secret"]),
            refresh_token=crypto.decrypt(self._key, rec["refresh_token"]),
            scopes=list(rec["scopes"]),
            created_at=rec["created_at"],
        )

    def delete(self, name: str) -> None:
        if name not in self._data["connections"]:
            raise KeyError(name)
        del self._data["connections"][name]
        self._write(self._data)

    def list_names(self) -> list[str]:
        return sorted(self._data["connections"].keys())

    def list_metadata(self) -> list[dict]:
        return [
            {
                "name": name,
                "provider": rec["provider"],
                "scopes": list(rec["scopes"]),
                "created_at": rec["created_at"],
            }
            for name, rec in sorted(self._data["connections"].items())
        ]
