from __future__ import annotations

import shutil
import subprocess

import pytest

from broker.ssh_ca import generate_ca, issue_certificate
from broker.ssh_krl import SshKeygenKrlWriter
from broker.ssh_validation import ssh_key_id

pytestmark = pytest.mark.skipif(
    shutil.which("ssh-keygen") is None,
    reason="ssh-keygen not installed; real KRL generation is untestable here",
)


def _write(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def test_real_krl_marks_revoked_cert_revoked(tmp_path):
    ca = generate_ca()
    ca_pub = str(tmp_path / "ca.pub")
    _write(ca_pub, ca.public_key_openssh + "\n")

    revoked_kid = ssh_key_id("claude-code", "web-1")
    ok_kid = ssh_key_id("claude-code", "db-1")

    def _cert_file(kid):
        cred = issue_certificate(ca.private_key_pem, key_id=kid, principal="deploy",
                                 ttl_minutes=15)
        p = str(tmp_path / (kid.replace(":", "_") + "-cert.pub"))
        _write(p, cred.certificate + "\n")
        return p

    revoked_cert = _cert_file(revoked_kid)
    ok_cert = _cert_file(ok_kid)

    krl = str(tmp_path / "krl")
    SshKeygenKrlWriter().write_krl(ca.public_key_openssh, [revoked_kid], krl)

    # ssh-keygen -Q -f <krl> <cert> exits non-zero if the cert is revoked.
    revoked_rc = subprocess.run(["ssh-keygen", "-Q", "-f", krl, revoked_cert],
                                capture_output=True).returncode
    ok_rc = subprocess.run(["ssh-keygen", "-Q", "-f", krl, ok_cert],
                           capture_output=True).returncode
    assert revoked_rc != 0, "revoked cert should be reported revoked"
    assert ok_rc == 0, "non-revoked cert should pass"
