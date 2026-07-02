from __future__ import annotations

from broker import crypto
from broker.encrypted_store import EncryptedStore


class CredentialDecryptionError(Exception):
    """Raised when a credential cannot be decrypted (wrong key or tampering)."""


class CredentialStore(EncryptedStore):
    _SECTION = "credentials"

    def store(self, name: str, value: str) -> None:
        self._entries()[name] = crypto.encrypt(self._key, value)
        self._write(self._data)

    def retrieve(self, name: str) -> str:
        entries = self._entries()
        if name not in entries:
            raise KeyError(name)
        try:
            return crypto.decrypt(self._key, entries[name])
        except crypto.CryptoDecryptionError as exc:
            raise CredentialDecryptionError(
                f"could not decrypt credential '{name}' (wrong password or tampered store)"
            ) from exc

    def delete(self, name: str) -> None:
        entries = self._entries()
        if name not in entries:
            raise KeyError(name)
        del entries[name]
        self._write(self._data)

    def list_names(self) -> list[str]:
        return sorted(self._entries().keys())
