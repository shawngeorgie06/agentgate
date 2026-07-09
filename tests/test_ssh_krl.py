from __future__ import annotations

import os

import pytest

from broker.ssh_krl import KrlWriteError, SshKeygenKrlWriter
from broker.ssh_validation import SshValidationError


class _RecordingRunner:
    """Captures the argv ssh-keygen would be called with, and the spec file
    contents, without invoking a real subprocess."""
    def __init__(self):
        self.argv = None
        self.spec_text = None

    def __call__(self, argv):
        self.argv = argv
        # argv is [ssh-keygen, -k, -f, out, -s, ca_pub, spec]; read the spec.
        self.spec_text = open(argv[-1], encoding="utf-8").read()


def test_write_krl_builds_fixed_argv_and_id_lines(tmp_path):
    rec = _RecordingRunner()
    w = SshKeygenKrlWriter(_runner=rec)
    out = str(tmp_path / "krl")
    w.write_krl("ssh-ed25519 AAAAfakeCA", ["agentgate:a:web-1", "agentgate:b:db-1"], out)
    assert rec.argv[:2] == ["ssh-keygen", "-k"]
    assert "-f" in rec.argv and out in rec.argv
    assert "-s" in rec.argv
    assert "id: agentgate:a:web-1" in rec.spec_text
    assert "id: agentgate:b:db-1" in rec.spec_text


def test_write_krl_rejects_injection_before_any_subprocess(tmp_path):
    # A key_id carrying a newline could inject a second KRL directive.
    # It must be rejected by validate_key_id BEFORE the runner is ever called.
    called = {"n": 0}
    def runner(argv):
        called["n"] += 1
    w = SshKeygenKrlWriter(_runner=runner)
    out = str(tmp_path / "krl")
    with pytest.raises(SshValidationError):
        w.write_krl("ssh-ed25519 AAAAfakeCA", ["agentgate:a:web-1\nserial: 1"], out)
    assert called["n"] == 0
    assert not os.path.exists(out)


def test_write_krl_maps_subprocess_failure_to_generic_error(tmp_path):
    def runner(argv):
        raise RuntimeError("ssh-keygen: /tmp/secret/path: No such file")
    w = SshKeygenKrlWriter(_runner=runner)
    with pytest.raises(KrlWriteError) as ei:
        w.write_krl("ssh-ed25519 AAAAfakeCA", ["agentgate:a:web-1"], str(tmp_path / "krl"))
    # No filesystem path / stderr leaks into the error message.
    assert "/tmp/secret/path" not in str(ei.value)
    assert "failed to generate KRL" in str(ei.value)


def test_temp_files_are_cleaned_up(tmp_path):
    rec = _RecordingRunner()
    w = SshKeygenKrlWriter(_runner=rec)
    w.write_krl("ssh-ed25519 AAAAfakeCA", ["agentgate:a:web-1"], str(tmp_path / "krl"))
    # The spec + ca-pub temp files created under the KRL's dir are gone.
    leftovers = [p for p in os.listdir(tmp_path) if p != "krl"]
    assert leftovers == []
