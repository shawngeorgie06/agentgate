"""Build the native AgentGate app without accessing Keychain or starting services."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import tempfile
import uuid

from broker.config import ConfigError
from broker.mac_service import LABEL, generate_plist


def _run(args, runner, action):
    try:
        result = (runner or subprocess.run)(args, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        raise ConfigError(f'Could not {action} the AgentGate app.') from None
    if result.returncode:
        raise ConfigError(f'Could not {action} the AgentGate app. Check that Xcode command-line tools are installed.')


def build_app(project_dir, config_dir, output, port=8765, *, runner=None):
    project, config, destination = (Path(p).expanduser().absolute() for p in (project_dir, config_dir, output))
    generate_plist(project, config, '/unused-helper', port)  # Shared strict port validation.
    if destination.suffix != '.app':
        raise ConfigError('App output must have a .app extension.')
    if config.resolve().is_relative_to(project.resolve()):
        raise ConfigError('Private AgentGate configuration must be outside the project directory.')
    source = project / 'native/AgentGateKeychain.swift'
    if not source.is_file():
        raise ConfigError('Native AgentGate source is missing.')
    destination.parent.mkdir(parents=True, exist_ok=True)
    parent_info = destination.parent.lstat()
    if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid() or parent_info.st_mode & 0o022:
        raise ConfigError('App destination must be an owner-controlled directory.')
    if destination.exists() or destination.is_symlink():
        info = destination.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ConfigError('Existing app must be an owner-controlled directory, not a symlink.')
    staging = Path(tempfile.mkdtemp(prefix='.agentgate-build-', dir=destination.parent))
    app = staging / 'AgentGate.app'
    backup = None
    try:
        contents = app / 'Contents'
        for directory in (app, contents, contents / 'MacOS', contents / 'Resources'):
            directory.mkdir(mode=0o700)
        binary = contents / 'MacOS/AgentGateKeychain'
        settings = {'python': str(project / '.venv/bin/python'), 'project_dir': str(project),
                    'config_dir': str(config), 'port': port, 'label': LABEL}
        metadata = {'CFBundleIdentifier': 'com.agentgate.app', 'CFBundleName': 'AgentGate',
                    'CFBundleExecutable': 'AgentGateKeychain', 'CFBundlePackageType': 'APPL',
                    'CFBundleVersion': '1', 'CFBundleShortVersionString': '1.0', 'LSUIElement': False,
                    'NSHighResolutionCapable': True}
        for path, data in ((contents / 'Info.plist', plistlib.dumps(metadata)),
                           (contents / 'Resources/settings.json', json.dumps(settings).encode())):
            path.write_bytes(data)
            path.chmod(0o600)
        _run(['/usr/bin/swiftc', str(source), '-o', str(binary), '-framework', 'Cocoa', '-framework', 'Security'], runner, 'compile')
        binary.chmod(0o700)
        _run(['/usr/bin/codesign', '--force', '--sign', '-', '--identifier', 'com.agentgate.app', str(app)], runner, 'sign')
        _run(['/usr/bin/codesign', '--verify', '--strict', str(app)], runner, 'verify')
        for item in app.rglob('*'):
            item.chmod(0o700 if item.is_dir() or item == binary else 0o600)
        if destination.exists():
            backup = destination.with_name('.agentgate-backup-' + uuid.uuid4().hex + '.app')
            os.replace(destination, backup)
        try:
            os.replace(app, destination)
        except BaseException:
            if backup is not None:
                os.replace(backup, destination)
                backup = None
            raise
        if backup is not None:
            shutil.rmtree(backup)
        return destination
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-dir', required=True)
    parser.add_argument('--config-dir', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--build-only', action='store_true', help='build app only; no Keychain access or service activation')
    args = parser.parse_args()
    try:
        build_app(args.project_dir, args.config_dir, args.output, args.port)
    except ConfigError as error:
        parser.exit(2, f'{error}\n')
    print('AgentGate app built. No Keychain changes or background service activation performed.')


if __name__ == '__main__':
    main()
