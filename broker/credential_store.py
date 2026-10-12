from __future__ import annotations

import base64
import json
import os
import threading
import tempfile

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Argon2id parameters (interactive-grade; tune up for production hardware).
_ARGON2_TIME_COST = 3
_ARGON2_MEMORY_COST = 64 * 1024  # KiB
_ARGON2_PARALLELISM = 4
_KEY_LEN = 32  # AES-256
_SALT_LEN = 16
_NONCE_LEN = 12  # 96-bit GCM nonce


class CredentialDecryptionError(Exception):
    """Raised when a credential cannot be decrypted (wrong key or tampering)."""


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


class CredentialStore:
    def __init__(self, path: str, master_password: str) -> None:
        self._lock = threading.RLock()
        self._path = path
        self._password = master_password.encode("utf-8")
        is_new = not os.path.exists(self._path)
        self._data = self._load()
        self._key = self._derive_key(_b64d(self._data["salt"]))
        if is_new:
            self._write(self._data)

    # --- persistence -----------------------------------------------------
    def _load(self) -> dict:
        if os.path.exists(self._path):
            with open(self._path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        return {"salt": _b64e(os.urandom(_SALT_LEN)), "credentials": {}}

    def _write(self, data: dict) -> None:
        directory = os.path.dirname(os.path.abspath(self._path))
        os.makedirs(directory, mode=0o700, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix='.agentgate-credentials-', dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(data, stream, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self._path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _derive_key(self, salt: bytes) -> bytes:
        return hash_secret_raw(
            secret=self._password,
            salt=salt,
            time_cost=_ARGON2_TIME_COST,
            memory_cost=_ARGON2_MEMORY_COST,
            parallelism=_ARGON2_PARALLELISM,
            hash_len=_KEY_LEN,
            type=Type.ID,
        )

    # --- public API ------------------------------------------------------
    def update(self, values: dict[str, str], *, delete=()) -> None:
        """Persist a complete encrypted candidate before publishing it in memory."""
        with self._lock:
            entries = dict(self._data["credentials"])
            for name in delete:
                entries.pop(name, None)
            for name, value in values.items():
                nonce = os.urandom(_NONCE_LEN)
                ciphertext = AESGCM(self._key).encrypt(nonce, value.encode("utf-8"), None)
                entries[name] = {"nonce": _b64e(nonce), "ciphertext": _b64e(ciphertext)}
            candidate = {**self._data, "credentials": entries}
            self._write(candidate)
            self._data = candidate

    def store(self, name: str, value: str) -> None:
        self.update({name: value})

    def retrieve(self, name: str) -> str:
        with self._lock:
            if name not in self._data["credentials"]:
                raise KeyError(name)
            entry = self._data["credentials"][name]
            try:
                plaintext = AESGCM(self._key).decrypt(
                    _b64d(entry["nonce"]), _b64d(entry["ciphertext"]), None
                )
            except InvalidTag as exc:
                raise CredentialDecryptionError(
                    f"could not decrypt credential '{name}' (wrong password or tampered store)"
                ) from exc
            return plaintext.decode("utf-8")

    def delete(self, name: str) -> None:
        with self._lock:
            if name not in self._data["credentials"]:
                raise KeyError(name)
            self.update({}, delete=(name,))

    def list_names(self) -> list[str]:
        with self._lock:
            return sorted(self._data["credentials"].keys())
