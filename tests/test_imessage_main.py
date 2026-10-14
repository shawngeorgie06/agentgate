import os
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest
import uvicorn

from broker import main as main_mod
from broker.config import Config, ConfigError
from broker.agent_registry import AgentRegistry
from broker.imessage_service import IMessageService


def _config(tmp_path):
    policies = tmp_path / 'policies.yaml'
    policies.write_text(textwrap.dedent("""
        policies:
          - name: default-deny
            agent: "*"
            credential: "*"
            auto_approve: false
            escalate: true
    """))
    return Config.from_env({
        'POLICIES_PATH': str(policies),
        'STATE_PATH': str(tmp_path / 'mode.json'),
        'LOGS_PATH': str(tmp_path / 'audit.log'),
        'CREDENTIALS_PATH': str(tmp_path / 'creds.json'),
        'AGENTGATE_MASTER_PASSWORD': 'pw',
    })


def _helper(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('#!/bin/sh\n')
    path.chmod(0o700)
    return path


def _build(tmp_path, environ):
    from broker.agent_registry import AgentRegistry
    cfg = _config(tmp_path)
    registry = AgentRegistry(tmp_path / 'agents.sqlite3')
    broker = main_mod.build_broker(cfg, 'pw')
    return main_mod.build_imessage_service(cfg, registry, broker, None, None, environ=environ)


def test_defaults_point_at_bin_directory_beside_credentials(tmp_path):
    _helper(tmp_path / 'bin' / 'imsg')
    _helper(tmp_path / 'bin' / 'agentgate-model')
    service = _build(tmp_path, environ={})
    assert service.status()['available'] is True


def test_env_overrides_select_helper_paths(tmp_path):
    custom = tmp_path / 'elsewhere'
    imsg = _helper(custom / 'imsg-custom')
    model = _helper(custom / 'model-custom')
    unset = _build(tmp_path, environ={})
    assert unset.status()['available'] is False
    service = _build(tmp_path, environ={'AGENTGATE_IMSG_PATH': str(imsg),
                                        'AGENTGATE_MODEL_HELPER': str(model)})
    assert service.status()['available'] is True


def test_empty_env_overrides_fall_back_to_defaults(tmp_path):
    _helper(tmp_path / 'bin' / 'imsg')
    _helper(tmp_path / 'bin' / 'agentgate-model')
    service = _build(tmp_path, environ={'AGENTGATE_IMSG_PATH': '', 'AGENTGATE_MODEL_HELPER': ''})
    assert service.status()['available'] is True


def test_missing_helpers_report_unavailable_without_crashing(tmp_path):
    service = _build(tmp_path, environ={})
    status = service.status()
    assert status['available'] is False
    assert status['enabled'] is False and status['paired'] is False and status['error'] is None


def test_unreadable_ledger_key_reports_unavailable_without_blocking_startup(tmp_path):
    _helper(tmp_path / 'bin' / 'imsg')
    _helper(tmp_path / 'bin' / 'agentgate-model')
    key = tmp_path / 'imessage-ledger.key'
    key.write_bytes(b'x' * 32)
    key.chmod(0o644)
    status = _build(tmp_path, environ={}).status()
    assert status['available'] is False
    assert status['error'] == 'ledger_unavailable'
    assert status['paired'] is False and status['running'] is False


async def test_app_mode_attaches_and_runs_imessage_service_for_app_lifetime(tmp_path, monkeypatch):
    events = []
    captured = []
    real_start, real_stop = IMessageService.start, IMessageService.stop

    async def start(self):
        events.append('start')
        await real_start(self)

    async def stop(self):
        events.append('stop')
        await real_stop(self)

    def fake_dashboard(app, broker, tools, operator_token, **kwargs):
        captured.append(broker)
        return app

    async def serve(self):
        self.started = True

    operator = tmp_path / 'operator.token'
    agent = tmp_path / 'agent.token'
    operator.write_text('o' * 40)
    agent.write_text('a' * 40)
    operator.chmod(0o600)
    agent.chmod(0o600)
    monkeypatch.setattr(IMessageService, 'start', start)
    monkeypatch.setattr(IMessageService, 'stop', stop)
    class _Terminal:
        def close(self):
            pass

    monkeypatch.setattr(main_mod, 'open_terminal', lambda: _Terminal())
    monkeypatch.setattr(uvicorn.Server, 'serve', serve)
    monkeypatch.setattr('broker.dashboard.create_dashboard', fake_dashboard)

    await main_mod._run_locked(_config(tmp_path), http=True, token_file=str(agent),
                               operator_token_file=str(operator), open_app=False)

    assert events == ['start', 'stop']
    assert isinstance(captured[0].imessage_service, IMessageService)
    assert captured[0].imessage_service.status()['running'] is False
    assert os.path.exists(tmp_path / 'agents.sqlite3')


def test_helper_overrides_resolve_tilde_and_relative_paths_to_absolute(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    _helper(home / 'tools' / 'imsg')
    _helper(tmp_path / 'rel' / 'model')
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.chdir(tmp_path)
    service = _build(tmp_path, environ={'AGENTGATE_IMSG_PATH': '~/tools/imsg',
                                        'AGENTGATE_MODEL_HELPER': 'rel/model'})
    assert service.status()['available'] is True
    assert service._imsg_path.is_absolute() and service._model_helper_path.is_absolute()


def test_credentials_path_tilde_expands_before_locating_helpers(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    _helper(home / 'agentgate' / 'bin' / 'imsg')
    _helper(home / 'agentgate' / 'bin' / 'agentgate-model')
    monkeypatch.setenv('HOME', str(home))
    registry = AgentRegistry(tmp_path / 'agents.sqlite3')
    config = SimpleNamespace(credentials_path='~/agentgate/creds.json')
    service = main_mod.build_imessage_service(config, registry, SimpleNamespace(audit=None), None, None, environ={})
    assert service.status()['available'] is True


def test_build_passes_broker_approval_queue_to_service(tmp_path, monkeypatch):
    _helper(tmp_path / 'bin' / 'imsg')
    _helper(tmp_path / 'bin' / 'agentgate-model')
    home = tmp_path / 'home'
    (home / 'agentgate').mkdir(parents=True)
    monkeypatch.setenv('HOME', str(home))
    registry = AgentRegistry(tmp_path / 'agents.sqlite3')
    config = SimpleNamespace(credentials_path='~/agentgate/creds.json')
    queue = object()
    service = main_mod.build_imessage_service(config, registry, SimpleNamespace(audit=None, approvals=queue),
                                              None, None, environ={})
    assert service._approvals is queue
