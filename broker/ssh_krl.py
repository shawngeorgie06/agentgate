from __future__ import annotations

import os
import subprocess
import tempfile

from typing import Callable, Protocol, runtime_checkable

from broker.ssh_validation import validate_key_id


class KrlWriteError(Exception):
    """Raised when KRL generation fails. Message is deliberately generic —
    ssh-keygen stderr can embed local filesystem paths and must never leak."""


@runtime_checkable
class KrlWriter(Protocol):
    def write_krl(self, ca_public_openssh: str, key_ids: list[str], out_path: str) -> None:
        ...


def _default_runner(argv: list[str]) -> None:
    # check=True raises CalledProcessError on non-zero exit; stderr is
    # captured (not inherited) so it cannot leak to the operator's console
    # uncontrolled — the caller maps any failure to a generic KrlWriteError.
    subprocess.run(argv, check=True, capture_output=True)


class SshKeygenKrlWriter:
    """Materializes an OpenSSH KRL via `ssh-keygen -k`. The CA public key and
    the revocation spec are passed as 0600 temp files (never argv); the argv
    is fixed and shell=False. Only the CA PUBLIC key is used."""

    def __init__(self, _runner: Callable[[list[str]], None] = _default_runner) -> None:
        self._runner = _runner

    def write_krl(self, ca_public_openssh: str, key_ids: list[str], out_path: str) -> None:
        # Sink re-validation: reject any key_id that could inject a KRL
        # directive (newline/control char) BEFORE writing the spec file. One
        # bad id fails the whole write closed — no partial KRL.
        validated = [validate_key_id(k) for k in key_ids]

        out_dir = os.path.dirname(os.path.abspath(out_path))
        os.makedirs(out_dir, exist_ok=True)
        spec_path = ca_path = None
        try:
            spec_path = _write_temp(out_dir, "".join(f"id: {k}\n" for k in validated))
            ca_path = _write_temp(out_dir, ca_public_openssh + "\n")
            argv = ["ssh-keygen", "-k", "-f", out_path, "-s", ca_path, spec_path]
            try:
                self._runner(argv)
            except Exception:
                raise KrlWriteError("failed to generate KRL") from None
        finally:
            for p in (spec_path, ca_path):
                if p is not None and os.path.exists(p):
                    os.remove(p)


def _write_temp(directory: str, text: str) -> str:
    fd, path = tempfile.mkstemp(dir=directory)
    try:
        os.chmod(path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
    except Exception:
        os.remove(path)
        raise
    return path
