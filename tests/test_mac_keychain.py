import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch
import pytest
from broker.mac_keychain import read_password, validate_password, KeychainError
from broker.credential_store import CredentialStore

def test_preserves_password_whitespace(tmp_path):
    helper = tmp_path / 'helper'; helper.write_text(''); helper.chmod(0o700)
    with patch('broker.mac_keychain.subprocess.run', return_value=subprocess.CompletedProcess([], 0, b' secret \n', b'')) as run:
        assert read_password(str(helper), str(tmp_path / 'credentials')) == ' secret \n'
        assert run.call_args.kwargs['timeout'] == 15

def test_safe_error(tmp_path):
    helper = tmp_path / 'helper'; helper.write_text(''); helper.chmod(0o700)
    with patch('broker.mac_keychain.subprocess.run', return_value=subprocess.CompletedProcess([], 1, b'secret', b'secret')):
        with pytest.raises(KeychainError, match='Could not unlock') as exc:
            read_password(str(helper), str(tmp_path / 'credentials'))
        assert 'secret' not in str(exc.value)

def test_rejects_symlink(tmp_path):
    target = tmp_path / 'real'; target.write_text(''); target.chmod(0o700)
    link = tmp_path / 'link'; link.symlink_to(target)
    with pytest.raises(KeychainError): read_password(str(link), 'credentials')

def test_validation_never_creates_store(tmp_path):
    path = tmp_path / 'credentials.json'
    assert not validate_password(str(path), 'password')
    assert not path.exists()

def test_validation_existing_store(tmp_path):
    path = tmp_path / 'credentials.json'; CredentialStore(str(path), 'correct').store('test', 'value'); path.chmod(0o600)
    assert validate_password(str(path), 'correct')
    assert not validate_password(str(path), 'wrong')

@pytest.mark.parametrize('output', [b'', b'x' * 4097, b'\xff', b'a\x00b'])
def test_rejects_invalid_helper_output(tmp_path, output):
    helper = tmp_path / 'helper'; helper.write_text(''); helper.chmod(0o700)
    with patch('broker.mac_keychain.subprocess.run', return_value=subprocess.CompletedProcess([], 0, output, b'')):
        with pytest.raises(KeychainError): read_password(str(helper), 'credentials')

def test_timeout_sanitized(tmp_path):
    helper = tmp_path / 'helper'; helper.write_text(''); helper.chmod(0o700)
    with patch('broker.mac_keychain.subprocess.run', side_effect=subprocess.TimeoutExpired('private', 15, output=b'secret')):
        with pytest.raises(KeychainError) as exc: read_password(str(helper), 'credentials')
        assert 'secret' not in str(exc.value)

def test_cli_invalid_password_silent(tmp_path):
    path = tmp_path / 'credentials.json'; CredentialStore(str(path), 'correct').store('test', 'value'); path.chmod(0o600)
    result = subprocess.run([sys.executable, '-m', 'broker.mac_keychain', 'validate', '--credentials-path', str(path)], input=b'wrong', capture_output=True)
    assert result.returncode == 1
    assert result.stdout == result.stderr == b''


def test_rejects_public_vault(tmp_path):
    path = tmp_path / 'credentials.json'; CredentialStore(str(path), 'correct').store('test', 'value'); path.chmod(0o644)
    assert not validate_password(str(path), 'correct')

def test_rejects_hardlinked_vault(tmp_path):
    path = tmp_path / 'credentials.json'; CredentialStore(str(path), 'correct').store('test', 'value'); path.chmod(0o600)
    os.link(path, tmp_path / 'alias')
    assert not validate_password(str(path), 'correct')
