from __future__ import annotations

import pytest

from broker import crypto


def test_roundtrip_encrypt_decrypt():
    salt = crypto.new_salt()
    key = crypto.derive_key("master-pw", salt)
    entry = crypto.encrypt(key, "s3cret-value")
    assert entry["nonce"] and entry["ciphertext"]
    assert "s3cret-value" not in entry["ciphertext"]
    assert crypto.decrypt(key, entry) == "s3cret-value"


def test_wrong_password_raises():
    salt = crypto.new_salt()
    entry = crypto.encrypt(crypto.derive_key("right-pw", salt), "v")
    wrong_key = crypto.derive_key("wrong-pw", salt)
    with pytest.raises(crypto.CryptoDecryptionError):
        crypto.decrypt(wrong_key, entry)


def test_new_salt_is_random():
    assert crypto.new_salt() != crypto.new_salt()


def test_corrupt_entry_raises_decryption_error():
    salt = crypto.new_salt()
    key = crypto.derive_key("pw", salt)
    # A hand-edited/corrupt store: non-base64 ciphertext and a missing nonce
    # must surface as CryptoDecryptionError, not a raw binascii.Error/KeyError.
    with pytest.raises(crypto.CryptoDecryptionError):
        crypto.decrypt(key, {"nonce": crypto.b64e(b"x" * 12), "ciphertext": "not!base64!"})
    with pytest.raises(crypto.CryptoDecryptionError):
        crypto.decrypt(key, {"ciphertext": crypto.b64e(b"whatever")})
