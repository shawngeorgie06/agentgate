import json
import plistlib
import subprocess
from pathlib import Path

import pytest

from broker.config import ConfigError
from broker.mac_install import build_app


def compiler(args, **kwargs):
    if args[0] == '/usr/bin/swiftc':
        Path(args[args.index('-o') + 1]).write_bytes(b'executable')
    return subprocess.CompletedProcess(args, 0, '', '')


def test_build_private_bundle_and_configuration(tmp_path):
    project = tmp_path / 'project'
    (project / 'native').mkdir(parents=True)
    (project / 'native/AgentGateKeychain.swift').write_text('sample')
    app = build_app(project, tmp_path / 'config', tmp_path / 'AgentGate.app', runner=compiler)
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    assert info['CFBundleIdentifier'] == 'com.agentgate.app'
    assert info['CFBundleExecutable'] == 'AgentGateKeychain'
    settings = json.loads((app / 'Contents/Resources/settings.json').read_text())
    assert settings['project_dir'] == str(project)
    assert settings['port'] == 8765
    assert (app / 'Contents/MacOS/AgentGateKeychain').stat().st_mode & 0o777 == 0o700
    assert (app / 'Contents/Resources/settings.json').stat().st_mode & 0o777 == 0o600


def test_failed_update_preserves_existing_bundle(tmp_path):
    project = tmp_path / 'project'
    (project / 'native').mkdir(parents=True)
    (project / 'native/AgentGateKeychain.swift').write_text('sample')
    app = build_app(project, tmp_path / 'config', tmp_path / 'AgentGate.app', runner=compiler)
    def fail(args, **kwargs):
        return subprocess.CompletedProcess(args, 1, '', 'private secret diagnostics')
    with pytest.raises(ConfigError, match='compile') as error:
        build_app(project, tmp_path / 'config', app, runner=fail)
    assert 'private secret' not in str(error.value)
    assert (app / 'Contents/MacOS/AgentGateKeychain').read_bytes() == b'executable'
