"""Operator-managed service permissions with atomic storage and conflict detection."""
from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

import yaml

from broker.policy_engine import PolicyEngine, PolicyError

RESOURCES = ('gmail:read', 'gmail:draft', 'gmail:send')
SERVICE_RESOURCES = {
    'gmail': RESOURCES,
    'github': ('github:read', 'github:write'),
}
MARKER = 'agentgate-permissions'
SERVICE_MARKERS = {'gmail': MARKER, 'github': MARKER + ':github'}


class PermissionConflict(ValueError):
    pass


class Permissions:
    def __init__(self, broker):
        self.broker = broker
        self.path = Path(broker.config.policies_path)

    def _snapshot(self):
        raw = self.path.read_bytes()
        errors = PolicyEngine.validate_file(str(self.path))
        if errors:
            raise PolicyError('The policy file is invalid. Repair it before editing permissions.')
        try:
            doc = yaml.safe_load(raw)
        except yaml.YAMLError:
            raise PolicyError('The policy file is invalid. Repair it before editing permissions.') from None
        return doc, hashlib.sha256(raw).hexdigest()

    def _agent(self, agent_id):
        registry = self.broker.agent_registry
        if registry is None:
            raise ValueError('Agent identities are unavailable.')
        agent = next((row for row in registry.list_agents() if row['id'] == agent_id), None)
        if agent is None:
            raise ValueError('Choose a registered agent.')
        return agent

    @staticmethod
    def _service(service):
        if service not in SERVICE_RESOURCES:
            raise ValueError('Choose Gmail or GitHub.')
        return service

    @staticmethod
    def _time_windows(doc, agent_id, service='gmail'):
        resources = SERVICE_RESOURCES[service]
        windows = []
        for rule in doc['policies']:
            if rule.get('agent') not in (agent_id, '*') or not rule.get('time_window'):
                continue
            for resource in resources:
                if rule.get('credential') in (resource, '*'):
                    windows.append({'resource': resource, 'policy': rule['name'], 'start': rule['time_window']['start'], 'end': rule['time_window']['end']})
        return windows

    def view(self, agent_id, service='gmail'):
        service = self._service(service)
        resources = SERVICE_RESOURCES[service]
        agent = self._agent(agent_id)
        doc, revision = self._snapshot()
        engine = PolicyEngine(doc['policies'])
        permissions = {}
        for resource in resources:
            decision = engine.evaluate(agent_id, resource)
            write = resource in ('gmail:send', 'github:write')
            permissions[resource] = ('ask' if write else 'allow') if decision.auto_approve else ('ask' if decision.escalate else 'deny')
        return {'agent': agent, 'connection': service, 'permissions': permissions, 'revision': revision,
                'time_windows': self._time_windows(doc, agent_id, service)}

    def save(self, agent_id, permissions, revision, *, service='gmail', acknowledge_time_windows=False):
        service = self._service(service)
        resources = SERVICE_RESOURCES[service]
        agent = self._agent(agent_id)
        if agent['status'] != 'active':
            raise ValueError('Only active agents can have their permissions changed.')
        if not isinstance(permissions, dict) or set(permissions) != set(resources):
            count = 'three Gmail' if service == 'gmail' else 'two GitHub'
            raise ValueError(f'Choose access for all {count} operations.')
        for resource, value in permissions.items():
            choices = ('ask', 'deny') if resource in ('gmail:send', 'github:write') else ('allow', 'ask', 'deny')
            if not isinstance(value, str) or value not in choices:
                message = 'Sending must require approval or be denied.' if resource == 'gmail:send' else 'Write operations must require approval or be denied.'
                raise ValueError('Invalid permission selection. ' + message)
        doc, current_revision = self._snapshot()
        if not isinstance(revision, str) or revision != current_revision:
            raise PermissionConflict('Permissions changed elsewhere. Reload and review before saving.')
        if self._time_windows(doc, agent_id, service) and acknowledge_time_windows is not True:
            raise ValueError('Explicitly acknowledge replacing existing time windows with all-time rules.')
        marker = SERVICE_MARKERS[service]
        managed = [{'name': f'{marker}:{agent_id}:{resource}', 'managed_by': marker,
                    'agent': agent_id, 'credential': resource,
                    'auto_approve': value == 'allow', 'escalate': value == 'ask'}
                   for resource, value in permissions.items()]
        retained = [rule for rule in doc['policies'] if not (rule.get('managed_by') == marker and rule.get('agent') == agent_id)]
        doc['policies'] = managed + retained
        fd, temporary = tempfile.mkstemp(prefix='.agentgate-permissions-', dir=self.path.parent)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                yaml.safe_dump(doc, stream, sort_keys=False)
                stream.flush()
                os.fsync(stream.fileno())
            candidate = PolicyEngine.from_file(temporary)
            # No await between conflict check and replace: operator and agent
            # policy writes execute on the broker's single event loop.
            if hashlib.sha256(self.path.read_bytes()).hexdigest() != current_revision:
                raise PermissionConflict('Permissions changed elsewhere. Reload and review before saving.')
            os.replace(temporary, self.path)
            self.broker.engine = candidate
            self.broker.invalidate_agent_requests()
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return self.view(agent_id, service)
