from __future__ import annotations

import json
import os

from broker import crypto


class EncryptedStore:
    """Encrypted JSON-file store shared by credential and connection stores.

    Provides Argon2id key derivation (one salt per store file), atomic writes
    with owner-only (0600) permissions, and mtime-based re-reads so a
    long-running broker sees writes made by the CLI process without a restart.
    Subclasses set `_SECTION` to the top-level key holding their entries.
    """

    _SECTION = "entries"

    def __init__(self, path: str, master_password: str) -> None:
        self._path = path
        is_new = not os.path.exists(self._path)
        self._data = self._read_file()
        self._mtime = self._current_mtime()
        # Derive the key once; the password itself is deliberately not retained.
        self._key = crypto.derive_key(master_password, self._data["salt"])
        if is_new:
            self._write(self._data)

    def _read_file(self) -> dict:
        if os.path.exists(self._path):
            with open(self._path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        return {"salt": crypto.new_salt(), self._SECTION: {}}

    def _current_mtime(self) -> float | None:
        try:
            return os.path.getmtime(self._path)
        except OSError:
            return None

    def _refresh(self) -> None:
        """Re-read from disk if another process wrote the file since we did."""
        mtime = self._current_mtime()
        if mtime == self._mtime:
            return
        data = self._read_file()
        if data["salt"] != self._data["salt"]:
            # The derived key no longer matches; decrypting would produce
            # garbage errors. Fail loudly instead.
            raise crypto.CryptoDecryptionError(
                "store salt changed on disk; restart to re-derive the key"
            )
        self._data = data
        self._mtime = mtime

    def _write(self, data: dict) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self._path)), exist_ok=True)
        tmp = f"{self._path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self._path)
        self._mtime = self._current_mtime()

    def _entries(self) -> dict:
        self._refresh()
        return self._data[self._SECTION]
