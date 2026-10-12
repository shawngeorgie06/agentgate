import json
import subprocess
import sys
from unittest.mock import patch

import pytest

from broker.apple_model import AppleModel


def helper(tmp_path):
    path = tmp_path / 'model'
    path.write_text('')
    path.chmod(0o700)
    return path


def response(data):
    return subprocess.CompletedProcess([], 0, json.dumps(data).encode(), b'')


def test_plan_private_stdin_and_strict_result(tmp_path):
    model = AppleModel(helper(tmp_path))
    plan = dict(action='gmail_unread', query='', message_id='', owner='', repo='', path='', ref='')
    with patch('broker.apple_model.subprocess.run', return_value=response({'ok': True, 'data': plan})) as run:
        assert model.plan('Check unread email', history='hello') == {'ok': True, 'data': plan}
        assert run.call_args.args[0] == [str(model.helper_path)]
        request = json.loads(run.call_args.kwargs['input'])
        assert request == {'mode': 'plan', 'prompt': 'Check unread email', 'history': 'hello'}
        assert run.call_args.kwargs['timeout'] == 60


def test_availability(tmp_path):
    model = AppleModel(helper(tmp_path))
    with patch('broker.apple_model.subprocess.run', return_value=response({'ok': True, 'data': {'available': False, 'reason': 'Apple Intelligence is not enabled.'}})):
        assert model.availability()['data']['available'] is False


@pytest.mark.parametrize('data', [
    {'ok': True, 'data': {'action': 'shell'}},
    {'ok': True, 'data': {'action': 'gmail_send'}},
    {'ok': True, 'data': {'action': 'chat', 'query': '', 'message_id': '', 'owner': '', 'repo': '', 'path': '', 'ref': '', 'token': 'secret'}},
    {'ok': True, 'data': {'action': 'chat', 'query': None}},
    {'ok': 'true', 'data': {}},
])
def test_rejects_unsafe_or_malformed_plan(tmp_path, data):
    with patch('broker.apple_model.subprocess.run', return_value=response(data)):
        assert AppleModel(helper(tmp_path)).plan('hello')['ok'] is False


@pytest.mark.parametrize('result', [
    subprocess.CompletedProcess([], 1, b'private text', b'secret'),
    subprocess.CompletedProcess([], 0, b'not json secret', b''),
    subprocess.CompletedProcess([], 0, b'x' * 65537, b''),
    response({'ok': False, 'reason': 'private secret', 'code': 'unexpected'}),
])
def test_safe_errors(tmp_path, result):
    with patch('broker.apple_model.subprocess.run', return_value=result):
        output = AppleModel(helper(tmp_path)).plan('hello')
        assert output['ok'] is False
        assert 'secret' not in json.dumps(output)


def test_timeout_sanitized(tmp_path):
    with patch('broker.apple_model.subprocess.run', side_effect=subprocess.TimeoutExpired('private', 60, output=b'secret')):
        assert AppleModel(helper(tmp_path)).plan('hello')['code'] == 'model_timeout'


def test_limits_before_launch(tmp_path):
    with patch('broker.apple_model.subprocess.run') as run:
        model = AppleModel(helper(tmp_path))
        assert not model.plan('x' * 2001)['ok']
        assert not model.answer('hi', 'x' * 6001)['ok']
        assert not model.plan('hello', history='x' * 4001)['ok']
        run.assert_not_called()


def test_symlink_and_writable_helper_rejected(tmp_path):
    real = helper(tmp_path)
    link = tmp_path / 'alias'
    link.symlink_to(real)
    assert not AppleModel(link).availability()['ok']
    real.chmod(0o777)
    assert not AppleModel(real).availability()['ok']


def test_answer_output_bound_and_command_prefix(tmp_path):
    model = AppleModel(helper(tmp_path))
    for text in ('x' * 1201, '/agent hello', '\x00hello'):
        with patch('broker.apple_model.subprocess.run', return_value=response({'ok': True, 'data': {'text': text}})):
            assert not model.answer('hello', '{}')['ok']
    with patch('broker.apple_model.subprocess.run', return_value=response({'ok': True, 'data': {'text': 'Hello!'}})):
        assert model.answer('hello', '{}')['data']['text'] == 'Hello!'


DUMP_HELPER = '''#!/bin/sh
env > __DUMP__
pwd -P > __CWD__
cat > /dev/null
printf '%s' '{"ok": true, "data": {"available": true, "reason": ""}}'
'''


def test_helper_gets_minimal_env_and_neutral_cwd(tmp_path, monkeypatch):
    monkeypatch.setenv('AGENTGATE_MASTER_PASSWORD', 'sentinel-secret')
    env_dump, cwd_dump = tmp_path / 'env.txt', tmp_path / 'cwd.txt'
    path = tmp_path / 'model'
    path.write_text(DUMP_HELPER.replace('__DUMP__', str(env_dump)).replace('__CWD__', str(cwd_dump)))
    path.chmod(0o700)
    assert AppleModel(path).availability()['ok'] is True
    seen = dict(line.split('=', 1) for line in env_dump.read_text().splitlines() if '=' in line)
    assert 'sentinel-secret' not in env_dump.read_text()
    assert 'AGENTGATE_MASTER_PASSWORD' not in seen
    assert set(seen) <= {'PATH', 'HOME', 'PWD', 'SHLVL', '_'}
    assert cwd_dump.read_text().strip() == '/'
