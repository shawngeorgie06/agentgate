from __future__ import annotations

import datetime
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization.ssh import (
    SSHCertificateType,
    load_ssh_public_identity,
)

from broker.ssh_ca import IssuedCredential, generate_ca, generate_keypair, issue_certificate
from broker.ssh_validation import SshValidationError


def test_generate_ca_produces_openssh_ed25519_pair():
    ca = generate_ca()
    assert ca.private_key_pem.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert ca.public_key_openssh.startswith("ssh-ed25519 ")
    # Loadable by the cryptography lib (what signing will do).
    serialization.load_ssh_private_key(ca.private_key_pem.encode(), password=None)


def test_keypairs_are_distinct_per_call():
    assert generate_keypair().public_key_openssh != generate_keypair().public_key_openssh


def test_private_key_never_in_repr():
    ca = generate_ca()
    assert "PRIVATE KEY" not in repr(ca)
    cred = issue_certificate(
        ca.private_key_pem, key_id="agentgate:cc:web-1", principal="deploy", ttl_minutes=15,
    )
    assert "PRIVATE KEY" not in repr(cred)


def test_issued_certificate_contents():
    ca = generate_ca()
    before = int(time.time())
    cred = issue_certificate(
        ca.private_key_pem, key_id="agentgate:cc:web-1", principal="deploy", ttl_minutes=15,
    )
    after = int(time.time())

    assert cred.private_key.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    cert = load_ssh_public_identity(cred.certificate.encode())
    cert.verify_cert_signature()  # self-consistent signature
    # Signed by OUR ca, not some other key.
    ca_pub = serialization.load_ssh_public_key(ca.public_key_openssh.encode())
    assert cert.signature_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ) == ca_pub.public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    assert cert.type == SSHCertificateType.USER
    assert cert.key_id == b"agentgate:cc:web-1"
    assert cert.valid_principals == [b"deploy"]
    assert before <= cert.valid_after <= after
    assert cert.valid_before == cert.valid_after + 15 * 60
    # Hardening: permit-pty only, nothing else; no force-command unless configured.
    assert cert.extensions == {b"permit-pty": b""}
    assert cert.critical_options == {}
    assert cert.serial > 0
    # expires_at is UTC ISO and matches the cert's own validity end.
    parsed = datetime.datetime.fromisoformat(cred.expires_at)
    assert int(parsed.timestamp()) == cert.valid_before


def test_force_command_lands_in_critical_options():
    ca = generate_ca()
    cred = issue_certificate(
        ca.private_key_pem, key_id="agentgate:cc:web-1", principal="deploy",
        ttl_minutes=15, force_command="echo ok",
    )
    cert = load_ssh_public_identity(cred.certificate.encode())
    assert cert.critical_options == {b"force-command": b"echo ok"}


def test_serials_and_keys_differ_across_grants():
    ca = generate_ca()
    a = issue_certificate(ca.private_key_pem, key_id="k", principal="deploy", ttl_minutes=15)
    b = issue_certificate(ca.private_key_pem, key_id="k", principal="deploy", ttl_minutes=15)
    assert a.private_key != b.private_key
    ca_cert = load_ssh_public_identity(a.certificate.encode())
    cb_cert = load_ssh_public_identity(b.certificate.encode())
    assert ca_cert.serial != cb_cert.serial


def test_sink_revalidates_principal_force_command_and_key_id():
    ca = generate_ca()
    with pytest.raises(SshValidationError):
        issue_certificate(ca.private_key_pem, key_id="k", principal="Root", ttl_minutes=15)
    with pytest.raises(SshValidationError):
        issue_certificate(ca.private_key_pem, key_id="k", principal="deploy\n", ttl_minutes=15)
    with pytest.raises(SshValidationError):
        issue_certificate(
            ca.private_key_pem, key_id="k", principal="deploy",
            ttl_minutes=15, force_command="echo hi\nrm -rf /",
        )
    with pytest.raises(SshValidationError):
        issue_certificate(ca.private_key_pem, key_id="k\nfake", principal="deploy", ttl_minutes=15)


def test_ttl_must_be_positive():
    ca = generate_ca()
    with pytest.raises(ValueError):
        issue_certificate(ca.private_key_pem, key_id="k", principal="deploy", ttl_minutes=0)
