"""Private macOS helper transport. Passwords never enter arguments or environment."""
from __future__ import annotations
import argparse
import os
import stat
import subprocess
import sys
from pathlib import Path
from broker.credential_store import CredentialStore

MAX_PASSWORD_BYTES = 4096
class KeychainError(ValueError):
    pass

def read_password(helper_path: str, credentials_path: str) -> str:
    try:
        helper = Path(helper_path).absolute()
        info = helper.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022 or not info.st_mode & 0o100:
            raise ValueError()
        result = subprocess.run([str(helper), 'read', '--account', str(Path(credentials_path).resolve())], capture_output=True, timeout=15, check=False)
        if result.returncode or not 0 < len(result.stdout) <= MAX_PASSWORD_BYTES:
            raise ValueError()
        password = result.stdout.decode('utf-8')
        if '\x00' in password:
            raise ValueError()
        return password
    except Exception:
        raise KeychainError('Could not unlock AgentGate with macOS Keychain. Open AgentGate to set up or unlock access.') from None

def validate_password(credentials_path: str, password: str) -> bool:
    try:
        path = Path(credentials_path)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            return False
        if not password or len(password.encode('utf-8')) > MAX_PASSWORD_BYTES or '\x00' in password:
            return False
        store = CredentialStore(str(path), password)
        names = store.list_names()
        if not names:  # An empty vault has no authentication evidence.
            return False
        for name in names:
            store.retrieve(name)
        return True
    except Exception:
        return False

def main() -> None:
    parser = argparse.ArgumentParser(description='AgentGate private unlock validation')
    parser.add_argument('command', choices=['validate'])
    parser.add_argument('--credentials-path', required=True)
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(MAX_PASSWORD_BYTES + 1)
        valid = len(raw) <= MAX_PASSWORD_BYTES and validate_password(args.credentials_path, raw.decode('utf-8'))
    except Exception:
        valid = False
    raise SystemExit(0 if valid else 1)

if __name__ == '__main__':
    main()
