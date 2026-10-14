"""Fixed, minimal environment for launching local helper binaries."""
from __future__ import annotations

from pathlib import Path


def minimal_helper_env():
    """Helpers see only PATH and HOME; broker secrets in the parent environment never reach them."""
    return {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(Path.home())}
