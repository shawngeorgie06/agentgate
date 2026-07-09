from __future__ import annotations

import hashlib
import hmac
import json

from broker import crypto
from broker.encrypted_store import EncryptedStore


class SshRevocationStore(EncryptedStore):
    """Revoked SSH certificate key_ids. Encrypted at rest: AES-GCM gives
    authenticated integrity so an attacker cannot silently drop a revocation
    entry without failing decryption. Keyed by a hash of the key_id so the
    plaintext key_id never appears in the JSON file."""

    _SECTION = "ssh_revocations"

    def _entry_id(self, key_id: str) -> str:
        # Keyed (HMAC) index, NOT a bare hash: the key_id format is public and
        # low-entropy, so an unkeyed hash would let a password-less reader of
        # the file test membership by hashing candidate names. HMAC with the
        # store's derived key makes membership-testing require the master key.
        return hmac.new(self._key, key_id.encode(), hashlib.sha256).hexdigest()

    def revoke(self, *, key_id: str, agent: str, resource: str,
               revoked_at: str, reason: str | None = None) -> None:
        record = {"key_id": key_id, "agent": agent, "resource": resource,
                  "revoked_at": revoked_at, "reason": reason}
        self._entries()[self._entry_id(key_id)] = crypto.encrypt(self._key, json.dumps(record))
        self._write(self._data)

    def unrevoke(self, key_id: str) -> bool:
        entries = self._entries()
        entry_id = self._entry_id(key_id)
        if entry_id not in entries:
            return False
        del entries[entry_id]
        self._write(self._data)
        return True

    def is_revoked(self, key_id: str) -> bool:
        return self._entry_id(key_id) in self._entries()

    def revoked_key_ids(self) -> list[str]:
        out = []
        for blob in self._entries().values():
            rec = json.loads(crypto.decrypt(self._key, blob))
            out.append(rec["key_id"])
        return sorted(out)

    def list_entries(self) -> list[dict]:
        out = []
        for blob in self._entries().values():
            rec = json.loads(crypto.decrypt(self._key, blob))
            out.append({"key_id": rec["key_id"], "agent": rec["agent"],
                        "resource": rec["resource"],
                        "revoked_at": rec["revoked_at"], "reason": rec["reason"]})
        return sorted(out, key=lambda x: x["key_id"])
