from __future__ import annotations

import datetime
import secrets
import time

from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization.ssh import (
    SSHCertificateBuilder,
    SSHCertificateType,
)

from broker.ssh_validation import (
    validate_force_command,
    validate_key_id,
    validate_principal,
)


@dataclass(frozen=True)
class SshKeypair:
    # repr=False: this PEM is a cleartext private key; a stray repr()/log
    # of the dataclass must never expose it.
    private_key_pem: str = field(repr=False)
    public_key_openssh: str


@dataclass(frozen=True)
class IssuedCredential:
    private_key: str = field(repr=False)
    certificate: str
    expires_at: str


def _new_ed25519() -> SshKeypair:
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode()
    pub = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode()
    return SshKeypair(private_key_pem=pem, public_key_openssh=pub)


def generate_ca() -> SshKeypair:
    return _new_ed25519()


def generate_keypair() -> SshKeypair:
    return _new_ed25519()


def issue_certificate(
    ca_private_key_pem: str,
    *,
    key_id: str,
    principal: str,
    ttl_minutes: int,
    force_command: str | None = None,
) -> IssuedCredential:
    """Generate a fresh keypair and sign a hardened user certificate.

    Sink re-validation: principal, force-command, and key_id are checked
    here regardless of what the caller already validated — no unvetted
    value may reach a certificate field (the db_grants discipline).
    Extensions are fixed to permit-pty only: no agent/port/X11 forwarding,
    no user-rc, and never configurable from a request.
    """
    principal = validate_principal(principal)
    key_id = validate_key_id(key_id)
    if force_command is not None:
        force_command = validate_force_command(force_command)
    if ttl_minutes < 1:
        raise ValueError("ttl_minutes must be >= 1")

    ca_key = serialization.load_ssh_private_key(ca_private_key_pem.encode(), password=None)
    user = _new_ed25519()
    user_pub = serialization.load_ssh_public_key(user.public_key_openssh.encode())

    valid_after = int(time.time())
    valid_before = valid_after + ttl_minutes * 60

    builder = (
        SSHCertificateBuilder()
        .public_key(user_pub)
        .serial(secrets.randbits(63))
        .type(SSHCertificateType.USER)
        .key_id(key_id.encode())
        .valid_principals([principal.encode()])
        .valid_after(valid_after)
        .valid_before(valid_before)
        .add_extension(b"permit-pty", b"")
    )
    if force_command is not None:
        builder = builder.add_critical_option(b"force-command", force_command.encode())
    cert = builder.sign(ca_key)

    expires_at = datetime.datetime.fromtimestamp(
        valid_before, tz=datetime.timezone.utc
    ).isoformat(timespec="seconds")
    return IssuedCredential(
        private_key=user.private_key_pem,
        certificate=cert.public_bytes().decode(),
        expires_at=expires_at,
    )
