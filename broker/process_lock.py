"""One broker per encrypted credential store; never unlink a held lock inode."""
from __future__ import annotations

import fcntl
import os
import stat
from pathlib import Path

from broker.config import ConfigError


class CredentialProcessLock:
    def __init__(self, path: str | Path):
        self.path = os.fspath(path)
        self._fd: int | None = None

    def __enter__(self):
        if self._fd is not None:
            raise ConfigError('Broker process lock is already held.')
        fd = None
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
                raise ConfigError('Broker process lock must be a private, owner-controlled regular file.')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ConfigError('An AgentGate broker is already running for this credential store.') from None
            self._fd = fd
            return self
        except OSError:
            if fd is not None:
                os.close(fd)
            raise ConfigError('Could not safely open the broker process lock.') from None
        except BaseException:
            if fd is not None:
                os.close(fd)
            raise

    def __exit__(self, *_):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
