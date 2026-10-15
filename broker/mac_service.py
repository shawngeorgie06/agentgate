"""Install a secret-free, per-user macOS launchd service definition."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import tempfile

import requests

from broker.config import ConfigError

LABEL = 'com.agentgate.broker'


def generate_plist(project_dir, config_dir, helper_path, port=8765):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ConfigError('HTTP port must be between 1 and 65535.')
    project, config, helper = (Path(p).expanduser().absolute() for p in (project_dir, config_dir, helper_path))
    env = {key: str(config / filename) for key, filename in {
        'POLICIES_PATH': 'policies.yaml', 'STATE_PATH': 'mode.json',
        'LOGS_PATH': 'audit.log', 'CREDENTIALS_PATH': 'credentials.json',
        'AGENTS_PATH': 'agents.sqlite3', 'GMAIL_CLIENT_PATH': 'oauth-client.json',
    }.items()}
    env['ESCALATION_TIMEOUT_SECONDS'] = '300'
    return {
        'Label': LABEL,
        'ProgramArguments': [str(project / '.venv/bin/python'), '-m', 'broker.main', '--app', '--no-open',
                             '--keychain-helper', str(helper), '--token-file', str(config / 'mcp-token'),
                             '--operator-token-file', str(config / 'operator-token'), '--port', str(port)],
        'WorkingDirectory': str(project), 'EnvironmentVariables': env,
        'RunAtLoad': True, 'KeepAlive': True, 'ThrottleInterval': 30,
        'Umask': 63, 'LimitLoadToSessionType': 'Aqua',
        'StandardOutPath': str(config / 'broker.stdout.log'),
        'StandardErrorPath': str(config / 'broker.stderr.log'),
    }


def _private_directory(path: Path, mode=0o700, *, preserve_existing=False):
    existed = path.exists()
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ConfigError('Service directory must be owned by the current user and cannot be a symlink.')
    if preserve_existing and existed:
        if info.st_mode & 0o022:
            raise ConfigError('Existing LaunchAgents directory must not be writable by other users.')
    else:
        os.chmod(path, mode)


def _private_log(path):
    fd = None
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise ConfigError('Service log must be an owner-controlled regular file.')
        os.fchmod(fd, 0o600)
    except OSError:
        raise ConfigError('Could not safely prepare private service logs.') from None
    finally:
        if fd is not None:
            os.close(fd)


def install(project_dir, config_dir, helper_path, port=8765, *, launch_agents_dir=None):
    definition = generate_plist(project_dir, config_dir, helper_path, port)
    config = Path(config_dir).expanduser().absolute()
    agents = Path(launch_agents_dir or Path.home() / 'Library/LaunchAgents').expanduser().absolute()
    _private_directory(config)
    _private_directory(agents, preserve_existing=True)
    for name in ('broker.stdout.log', 'broker.stderr.log'):
        _private_log(config / name)
    destination = agents / (LABEL + '.plist')
    if destination.is_symlink():
        raise ConfigError('Service definition cannot be a symlink.')
    fd, temporary = tempfile.mkstemp(prefix='.agentgate-', dir=agents)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            plistlib.dump(definition, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return destination


def _invoke(arguments, runner=None):
    try:
        return (runner or subprocess.run)(['/bin/launchctl', *arguments], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        raise ConfigError('Could not communicate with the macOS background service manager.') from None


def _domain(uid):
    return f'gui/{os.getuid() if uid is None else uid}'


def start(plist_path, *, runner=None, uid=None):
    result = _invoke(['bootstrap', _domain(uid), str(Path(plist_path).expanduser().absolute())], runner)
    if result.returncode:
        raise ConfigError('Could not start AgentGate background service. Check whether it is already loaded and inspect its private logs.')


def stop(*, runner=None, uid=None):
    result = _invoke(['bootout', _domain(uid) + '/' + LABEL], runner)
    if result.returncode:
        # A stopped job is already in the requested state, but do not mask
        # unrelated launchctl failures while a job remains registered.
        if status(runner=runner, uid=uid)['loaded']:
            raise ConfigError('Could not stop AgentGate background service.')


def status(*, runner=None, uid=None):
    result = _invoke(['print', _domain(uid) + '/' + LABEL], runner)
    # Never return arbitrary launchctl output/environment to browser clients.
    return {'loaded': result.returncode == 0,
            'running': result.returncode == 0 and 'state = running' in result.stdout}


def uninstall(plist_path=None, *, runner=None, uid=None):
    stop(runner=runner, uid=uid)
    path = Path(plist_path or Path.home() / 'Library/LaunchAgents' / (LABEL + '.plist'))
    if path.is_symlink():
        raise ConfigError('Service definition cannot be a symlink.')
    path.unlink(missing_ok=True)


def is_ready(operator_token, *, port=8765, get=None):
    """Probe only the fixed loopback operator API; never log bearer material."""
    if type(port) is not int or not 1 <= port <= 65535:
        raise ConfigError('HTTP port must be between 1 and 65535.')
    try:
        response = (get or requests.get)(
            f'http://127.0.0.1:{port}/api/status',
            headers={'Authorization': 'Bearer ' + operator_token},
            timeout=2, allow_redirects=False,
        )
        return response.status_code == 200 and response.json().get('ok') is True
    except (requests.RequestException, ValueError, AttributeError):
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-dir', required=True)
    parser.add_argument('--config-dir', required=True)
    parser.add_argument('--helper-path', required=True)
    parser.add_argument('--port', type=int, default=8765)
    args = parser.parse_args()
    try:
        install(args.project_dir, args.config_dir, args.helper_path, args.port)
    except ConfigError as error:
        parser.exit(2, f'{error}\n')
    print('AgentGate background service definition installed; it has not been started.')


if __name__ == '__main__':
    main()
