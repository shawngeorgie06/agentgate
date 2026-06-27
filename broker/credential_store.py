from __future__ import annotations

import json
import os

from broker import crypto


class CredentialDecryptionError(Exception):
    """Raised when a credential cannot be decrypted (wrong key or tampering)."""


class CredentialStore:
    def __init__(self, path: str, master_password: str) -> None:
        self._path = path
        self._password = master_password
        is_new = not os.path.exists(self._path)
        self._data = self._load()
        self._key = crypto.derive_key(self._password, self._data["salt"])
        if is_new:
            self._write(self._data)

    def _load(self) -> dict:
        if os.path.exists(self._path):
            with open(self._path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        return {"salt": crypto.new_salt(), "credentials": {}}

    def _write(self, data: dict) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self._path)), exist_ok=True)
        tmp = f"{self._path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, self._path)

    def store(self, name: str, value: str) -> None:
        self._data["credentials"][name] = crypto.encrypt(self._key, value)
        self._write(self._data)

    def retrieve(self, name: str) -> str:
        if name not in self._data["credentials"]:
            raise KeyError(name)
        try:
            return crypto.decrypt(self._key, self._data["credentials"][name])
        except crypto.CryptoDecryptionError as exc:
            raise CredentialDecryptionError(
                f"could not decrypt credential '{name}' (wrong password or tampered store)"
            ) from exc

    def delete(self, name: str) -> None:
        if name not in self._data["credentials"]:
            raise KeyError(name)
        del self._data["credentials"][name]
        self._write(self._data)

    def list_names(self) -> list[str]:
        return sorted(self._data["credentials"].keys())
