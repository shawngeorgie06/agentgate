import plistlib
from unittest.mock import Mock

import pytest

from broker.config import ConfigError
from broker.mac_service import generate_plist, install, start, stop, status, uninstall


def test_plist_is_absolute_supervised_and_contains_no_inherited_secret(tmp_path, monkeypatch):
    monkeypatch.setenv('AGENTGATE_MASTER_PASSWORD', 'never-export-this')
    project = tmp_path / 'project with spaces'
    config = tmp_path / 'private'
    helper = tmp_path / 'helper'
    result = generate_plist(project, config, helper)
    assert result['ProgramArguments'][0] == str(project / '.venv/bin/python')
    assert result['ProgramArguments'][1:4] == ['-m', 'broker.mac_service', 'run']
    assert '--no-open' in result['ProgramArguments']
    assert '--keychain-helper' in result['ProgramArguments']
    assert result['KeepAlive'] == {'SuccessfulExit': False}
    assert result['RunAtLoad'] is True
    assert result['Umask'] == 63
    assert result['LimitLoadToSessionType'] == 'Aqua'
    assert 'never-export-this' not in plistlib.dumps(result).decode()
    assert 'AGENTGATE_MASTER_PASSWORD' not in result['EnvironmentVariables']


def test_launchd_stops_retrying_configuration_errors(tmp_path, monkeypatch, capsys):
    from broker import mac_service
    from broker import main as broker_main
    monkeypatch.setattr('sys.argv', ['mac_service', 'run', '--keychain-helper', '/sample/helper'])

    async def failed_start(**kwargs):
        raise ConfigError('Could not unlock AgentGate with macOS Keychain.')

    monkeypatch.setattr(broker_main, 'run', failed_start)
    # launchd's SuccessfulExit condition must see a deliberate pause, not a crash.
    mac_service.main()
    error = capsys.readouterr().err
    assert 'Could not unlock AgentGate' in error
    assert 'Background startup paused.' in error


@pytest.mark.parametrize('failure', [None, RuntimeError('unexpected failure')])
def test_launchd_still_restarts_unexpected_broker_exits(monkeypatch, failure):
    from broker import mac_service
    from broker import main as broker_main
    monkeypatch.setattr('sys.argv', ['mac_service', 'run'])

    async def ended(**kwargs):
        if failure is not None:
            raise failure

    monkeypatch.setattr(broker_main, 'run', ended)
    if failure is None:
        with pytest.raises(SystemExit) as error:
            mac_service.main()
        assert error.value.code == 1
    else:
        with pytest.raises(RuntimeError, match='unexpected failure'):
            mac_service.main()


def test_direct_broker_command_keeps_nonzero_configuration_exit(monkeypatch):
    from broker import main as broker_main
    monkeypatch.setattr('sys.argv', ['broker'])

    async def failed_start(**kwargs):
        raise ConfigError('Invalid configuration.')

    monkeypatch.setattr(broker_main, 'run', failed_start)
    with pytest.raises(SystemExit) as error:
        broker_main.main()
    assert error.value.code == 2


def test_plist_gives_approvals_long_enough_to_answer_by_text(tmp_path):
    # Approving from iMessage means noticing a text and replying; a minute is often too short.
    result = generate_plist(tmp_path / 'project', tmp_path / 'config', tmp_path / 'helper')
    assert result['EnvironmentVariables']['ESCALATION_TIMEOUT_SECONDS'] == '300'


def test_install_writes_private_files_but_does_not_activate(tmp_path):
    launch_agents = tmp_path / 'LaunchAgents'
    path = install(tmp_path / 'project', tmp_path / 'config', tmp_path / 'helper', launch_agents_dir=launch_agents)
    assert path.stat().st_mode & 0o777 == 0o600
    assert (tmp_path / 'config').stat().st_mode & 0o777 == 0o700
    assert plistlib.loads(path.read_bytes())['Label'] == 'com.agentgate.broker'
    for name in ('broker.stdout.log', 'broker.stderr.log'):
        assert (tmp_path / 'config' / name).stat().st_mode & 0o777 == 0o600


def test_launchctl_commands_are_argv_not_shell(tmp_path):
    runner = Mock(return_value=Mock(returncode=0, stdout='state = running', stderr=''))
    path = tmp_path / 'service.plist'
    start(path, runner=runner, uid=501)
    assert runner.call_args.args[0] == ['/bin/launchctl', 'bootstrap', 'gui/501', str(path)]
    assert runner.call_args.kwargs.get('shell', False) is False
    stop(runner=runner, uid=501)
    assert runner.call_args.args[0][-1] == 'gui/501/com.agentgate.broker'
    assert status(runner=runner, uid=501)['loaded'] is True
    path.write_text('plist')
    uninstall(path, runner=runner, uid=501)
    assert not path.exists()


@pytest.mark.parametrize('port', [0, 65536, True, '8765'])
def test_invalid_port(port, tmp_path):
    with pytest.raises(ConfigError):
        generate_plist(tmp_path, tmp_path, tmp_path / 'helper', port)


def test_installer_rejects_symlinked_config_without_touching_target(tmp_path):
    real = tmp_path / 'real'
    real.mkdir(mode=0o755)
    config = tmp_path / 'config'
    config.symlink_to(real, target_is_directory=True)
    with pytest.raises(ConfigError):
        install(tmp_path / 'project', config, tmp_path / 'helper', launch_agents_dir=tmp_path / 'agents')
    assert real.stat().st_mode & 0o777 == 0o755


def test_status_does_not_return_arbitrary_launchctl_output():
    runner = Mock(return_value=Mock(returncode=0, stdout='state = running\nsecret = value', stderr='secret'))
    assert status(runner=runner) == {'loaded': True, 'running': True}


def test_readiness_checks_only_loopback_with_bounded_authenticated_request():
    from broker.mac_service import is_ready
    response = Mock(status_code=200)
    response.json.return_value = {'ok': True, 'data': {}}
    get = Mock(return_value=response)
    assert is_ready('private-token', port=8765, get=get)
    assert get.call_args.args == ('http://127.0.0.1:8765/api/status',)
    assert get.call_args.kwargs['allow_redirects'] is False
    response.status_code = 401
    assert not is_ready('private-token', get=get)


def test_install_preserves_existing_launchagents_permissions(tmp_path):
    agents = tmp_path / 'agents'
    agents.mkdir(mode=0o755)
    install(tmp_path / 'project', tmp_path / 'config', tmp_path / 'helper', launch_agents_dir=agents)
    assert agents.stat().st_mode & 0o777 == 0o755
