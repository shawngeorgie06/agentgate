"""Exercise the compiled helper without accessing real Keychain items."""
import os
from pathlib import Path
import pty
import shutil
import subprocess
import sys

import pytest

from broker.mac_install import build_app


pytestmark = pytest.mark.skipif(
    sys.platform != 'darwin' or shutil.which('swiftc') is None,
    reason='Native helper requires macOS and the Swift compiler.',
)


@pytest.fixture(scope='module')
def native_helper(tmp_path_factory):
    directory = tmp_path_factory.mktemp('native-keychain')
    app = build_app(Path(__file__).resolve().parents[1], directory / 'config', directory / 'AgentGate.app')
    return app / 'Contents/MacOS/AgentGateKeychain'


def test_native_helper_refuses_password_output_to_terminal(native_helper):
    master, slave = pty.openpty()
    try:
        result = subprocess.run(
            [str(native_helper), 'read', '--account', '/nonexistent/agentgate-terminal-test'],
            stdin=subprocess.DEVNULL, stdout=slave, stderr=subprocess.PIPE, timeout=10,
        )
        assert result.returncode == 2
        assert b'terminal' in result.stderr
        os.set_blocking(master, False)
        with pytest.raises(BlockingIOError):
            os.read(master, 1)
    finally:
        os.close(slave)
        os.close(master)


def test_native_bundle_configuration_is_valid(native_helper):
    result = subprocess.run([str(native_helper), '--check-config'], capture_output=True, timeout=10)
    assert result.returncode == 0
    assert result.stdout == result.stderr == b''
