import yaml
import pytest

from broker.permissions import Permissions, PermissionConflict
from tests.test_permissions import setup, selections


def github_selections(read='allow', write='ask'):
    return {'github:read': read, 'github:write': write}


def test_github_rules_are_scoped_and_preserve_gmail_managed_rules(tmp_path):
    broker, _, _, _, permissions = setup(tmp_path)
    gmail = permissions.save('local-agent', selections(), permissions.view('local-agent')['revision'])
    github = permissions.view('local-agent', service='github')
    assert github['connection'] == 'github'
    assert github['permissions'] == {'github:read': 'ask', 'github:write': 'ask'}

    saved_github = permissions.save('local-agent', github_selections('allow', 'deny'),
                                    github['revision'], service='github')
    assert saved_github['permissions'] == github_selections('allow', 'deny')
    assert broker.engine.evaluate('local-agent', 'github:read').auto_approve is True
    write = broker.engine.evaluate('local-agent', 'github:write')
    assert not write.auto_approve and not write.escalate
    assert broker.engine.evaluate('local-agent', 'gmail:read').auto_approve is True

    policies = yaml.safe_load(open(broker.config.policies_path))['policies']
    assert any(row.get('managed_by') == 'agentgate-permissions' and row.get('credential') == 'gmail:read' for row in policies)
    assert any(row.get('managed_by') == 'agentgate-permissions:github' and row.get('credential') == 'github:read' for row in policies)

    refreshed = permissions.view('local-agent')
    gmail_again = permissions.save('local-agent', selections(read='deny'), refreshed['revision'])
    assert gmail_again['permissions']['gmail:read'] == 'deny'
    assert broker.engine.evaluate('local-agent', 'github:read').auto_approve is True


@pytest.mark.parametrize('bad', [
    {'github:read': 'allow', 'github:write': 'allow'},
    {'github:read': 'deny'},
    {'github:read': True, 'github:write': 'ask'},
])
def test_invalid_github_permissions_do_not_modify_yaml(tmp_path, bad):
    broker, _, _, _, permissions = setup(tmp_path)
    path = broker.config.policies_path
    before = open(path, 'rb').read()
    with pytest.raises(ValueError):
        permissions.save('local-agent', bad, permissions.view('local-agent', 'github')['revision'], service='github')
    assert open(path, 'rb').read() == before


def test_github_time_window_acknowledgment_is_service_scoped(tmp_path):
    broker, _, _, _, permissions = setup(tmp_path)
    with open(broker.config.policies_path, 'w') as stream:
        yaml.safe_dump({'policies': [{
            'name': 'github-hours', 'agent': 'local-agent', 'credential': 'github:read',
            'auto_approve': True, 'time_window': {'start': '09:00', 'end': '17:00'},
        }]}, stream)
    before = open(broker.config.policies_path, 'rb').read()
    view = permissions.view('local-agent', 'github')
    assert view['time_windows'][0]['resource'] == 'github:read'
    with pytest.raises(ValueError, match='acknowledge'):
        permissions.save('local-agent', github_selections(), view['revision'], service='github')
    assert open(broker.config.policies_path, 'rb').read() == before
