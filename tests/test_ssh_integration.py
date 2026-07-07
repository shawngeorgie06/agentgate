# tests/test_ssh_integration.py
from __future__ import annotations

import os
import subprocess
import time

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("AGENTGATE_TEST_SSH_HOST"),
    reason=(
        "set AGENTGATE_TEST_SSH_HOST (and optionally AGENTGATE_TEST_SSH_PORT, "
        "AGENTGATE_TEST_SSH_PRINCIPAL, AGENTGATE_TEST_SSH_CA_PEM) to run against a real "
        "sshd whose sshd_config trusts the CA via TrustedUserCAKeys"
    ),
)


def _target():
    return dict(
        host=os.environ["AGENTGATE_TEST_SSH_HOST"],
        port=int(os.environ.get("AGENTGATE_TEST_SSH_PORT", "22")),
        principal=os.environ.get("AGENTGATE_TEST_SSH_PRINCIPAL", "agentgate-itest"),
    )


def _ca_pem(tmp_path):
    # Use the operator-provided CA (the one the server already trusts) when
    # given; otherwise generate one — which only works if the server trusts it.
    path = os.environ.get("AGENTGATE_TEST_SSH_CA_PEM")
    if path:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    from broker.ssh_ca import generate_ca
    return generate_ca().private_key_pem


def _ssh(tmp_path, private_key, certificate, target, command):
    key = tmp_path / "id_agentgate"
    key.write_text(private_key)
    key.chmod(0o600)
    (tmp_path / "id_agentgate-cert.pub").write_text(certificate)
    return subprocess.run(
        [
            "ssh", "-i", str(key),
            "-o", f"CertificateFile={tmp_path / 'id_agentgate-cert.pub'}",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes",
            "-p", str(target["port"]),
            f"{target['principal']}@{target['host']}",
            command,
        ],
        capture_output=True, text=True, timeout=30,
    )


def test_cert_login_expiry_and_force_command(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization.ssh import (
        SSHCertificateBuilder, SSHCertificateType,
    )

    from broker.ssh_ca import generate_keypair, issue_certificate

    target = _target()
    ca_pem = _ca_pem(tmp_path)

    # 1. A freshly issued cert logs in as the pinned principal.
    cred = issue_certificate(
        ca_pem, key_id="agentgate:itest:login", principal=target["principal"], ttl_minutes=5,
    )
    result = _ssh(tmp_path, cred.private_key, cred.certificate, target, "echo login-ok")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "login-ok"

    # 2. An expired cert is refused (built test-locally with a past window).
    ca_key = serialization.load_ssh_private_key(ca_pem.encode(), password=None)
    pair = generate_keypair()
    user_pub = serialization.load_ssh_public_key(pair.public_key_openssh.encode())
    now = int(time.time())
    expired = (
        SSHCertificateBuilder()
        .public_key(user_pub).serial(1).type(SSHCertificateType.USER)
        .key_id(b"agentgate:itest:expired")
        .valid_principals([target["principal"].encode()])
        .valid_after(now - 7200).valid_before(now - 3600)
        .add_extension(b"permit-pty", b"")
        .sign(ca_key)
    )
    result = _ssh(
        tmp_path, pair.private_key_pem, expired.public_bytes().decode(), target, "echo bad",
    )
    assert result.returncode != 0  # sshd refuses the expired certificate

    # 3. force-command overrides whatever the client asks to run.
    forced = issue_certificate(
        ca_pem, key_id="agentgate:itest:forced", principal=target["principal"],
        ttl_minutes=5, force_command="echo forced-ok",
    )
    result = _ssh(tmp_path, forced.private_key, forced.certificate, target, "echo something-else")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "forced-ok"
