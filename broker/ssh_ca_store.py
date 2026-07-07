from __future__ import annotations

import datetime

from broker import crypto
from broker.encrypted_store import EncryptedStore
from broker.ssh_ca import generate_ca


class SshCaExistsError(Exception):
    """Raised when initialize() would overwrite an existing CA. Re-keying
    every enrolled server's trust must be deliberate, never accidental."""


class SshCaStore(EncryptedStore):
    """Holds the single SSH CA keypair: private key encrypted at rest,
    public line stored readable (it is public material operators paste
    into sshd_config)."""

    _SECTION = "ssh_ca"
    _KEY = "ca"

    def initialize(self) -> str:
        entries = self._entries()
        if self._KEY in entries:
            raise SshCaExistsError("ssh CA already initialized")
        ca = generate_ca()
        entries[self._KEY] = {
            "private_pem": crypto.encrypt(self._key, ca.private_key_pem),
            "public_line": ca.public_key_openssh,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(
                timespec="seconds"
            ),
        }
        self._write(self._data)
        return ca.public_key_openssh

    def is_initialized(self) -> bool:
        return self._KEY in self._entries()

    def load_private_pem(self) -> str:
        entries = self._entries()
        if self._KEY not in entries:
            raise KeyError("ssh CA not initialized")
        return crypto.decrypt(self._key, entries[self._KEY]["private_pem"])

    def public_line(self) -> str:
        entries = self._entries()
        if self._KEY not in entries:
            raise KeyError("ssh CA not initialized")
        return entries[self._KEY]["public_line"]
