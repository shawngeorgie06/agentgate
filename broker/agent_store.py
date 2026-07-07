from __future__ import annotations

import hashlib
import hmac
import secrets

from broker import crypto
from broker.encrypted_store import EncryptedStore


def _digest(agent_key: str) -> str:
    return hashlib.sha256(agent_key.encode("utf-8")).hexdigest()


class AgentStore(EncryptedStore):
    """Registered agent identities.

    An agent name is only an identity claim; the high-entropy key issued at
    registration is what proves it. The key is shown once at registration and
    never stored — only an encrypted SHA-256 digest is kept, so neither a
    stolen store file nor the master password alone reveals a usable key.
    """

    _SECTION = "agents"

    def register(self, name: str) -> str:
        if not isinstance(name, str) or not name or not name.isprintable():
            raise ValueError("agent name must be non-empty printable text")
        entries = self._entries()
        if name in entries:
            raise ValueError(f"agent '{name}' is already registered")
        agent_key = secrets.token_urlsafe(32)
        entries[name] = crypto.encrypt(self._key, _digest(agent_key))
        self._write(self._data)
        return agent_key

    def verify(self, name: str, agent_key: str) -> bool:
        entries = self._entries()
        if name not in entries:
            return False
        try:
            expected = crypto.decrypt(self._key, entries[name])
        except crypto.CryptoDecryptionError:
            return False
        return hmac.compare_digest(expected, _digest(agent_key))

    def delete(self, name: str) -> None:
        entries = self._entries()
        if name not in entries:
            raise KeyError(name)
        del entries[name]
        self._write(self._data)

    def list_names(self) -> list[str]:
        return sorted(self._entries().keys())
