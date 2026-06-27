from __future__ import annotations

import base64
import os

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


class CryptoDecryptionError(Exception):
    """Raised when ciphertext cannot be decrypted (wrong key or tampering)."""


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def new_salt() -> str:
    return b64e(os.urandom(_SALT_LEN))


def derive_key(password: str, salt_b64: str) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=b64d(salt_b64),
        time_cost=_ARGON2_TIME_COST,
        memory_cost=_ARGON2_MEMORY_COST,
        parallelism=_ARGON2_PARALLELISM,
        hash_len=_KEY_LEN,
        type=Type.ID,
    )


def encrypt(key: bytes, plaintext: str) -> dict:
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return {"nonce": b64e(nonce), "ciphertext": b64e(ciphertext)}


def decrypt(key: bytes, entry: dict) -> str:
    try:
        plaintext = AESGCM(key).decrypt(b64d(entry["nonce"]), b64d(entry["ciphertext"]), None)
    except InvalidTag as exc:
        raise CryptoDecryptionError("could not decrypt (wrong password or tampered store)") from exc
    return plaintext.decode("utf-8")
