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
