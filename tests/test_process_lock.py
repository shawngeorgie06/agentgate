import os
import subprocess
import sys

import pytest

from broker.config import ConfigError
from broker.process_lock import CredentialProcessLock


def test_lock_excludes_other_process_and_can_be_reused(tmp_path):
    path = tmp_path / 'store.broker.lock'
    probe = 'from broker.process_lock import CredentialProcessLock; import sys;\nwith CredentialProcessLock(sys.argv[1]): pass'
    with CredentialProcessLock(path):
        result = subprocess.run([sys.executable, '-c', probe, str(path)], capture_output=True)
        assert result.returncode != 0
        assert b'already running' in result.stderr
        inode = path.stat().st_ino
        assert path.stat().st_mode & 0o777 == 0o600
    assert path.stat().st_ino == inode
    with CredentialProcessLock(path):
        pass


def test_symlink_is_rejected_without_changing_target(tmp_path):
    target = tmp_path / 'target'
    target.write_text('unchanged')
    path = tmp_path / 'lock'
    path.symlink_to(target)
    with pytest.raises(ConfigError):
        with CredentialProcessLock(path):
            pass
    assert target.read_text() == 'unchanged'


def test_nonregular_and_shared_lock_are_rejected(tmp_path):
    path = tmp_path / 'lock'
    path.mkdir()
    with pytest.raises(ConfigError):
        with CredentialProcessLock(path):
            pass
    path.rmdir()
    path.touch(mode=0o644)
    with pytest.raises(ConfigError):
        with CredentialProcessLock(path):
            pass
