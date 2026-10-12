"""Operator-managed Gmail policies with atomic storage and conflict detection."""
from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

import yaml

from broker.policy_engine import PolicyEngine, PolicyError

RESOURCES = ('gmail:read', 'gmail:draft', 'gmail:send')
MARKER = 'agentgate-permissions'


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
    def _time_windows(doc, agent_id):
        windows = []
        for rule in doc['policies']:
            if rule.get('agent') not in (agent_id, '*') or not rule.get('time_window'):
                continue
            for resource in RESOURCES:
                if rule.get('credential') in (resource, '*'):
                    windows.append({'resource': resource, 'policy': rule['name'], 'start': rule['time_window']['start'], 'end': rule['time_window']['end']})
        return windows

    def view(self, agent_id):
        agent = self._agent(agent_id)
        doc, revision = self._snapshot()
        engine = PolicyEngine(doc['policies'])
        permissions = {}
        for resource in RESOURCES:
            decision = engine.evaluate(agent_id, resource)
            permissions[resource] = ('ask' if resource == 'gmail:send' else 'allow') if decision.auto_approve else ('ask' if decision.escalate else 'deny')
        return {'agent': agent, 'connection': 'gmail', 'permissions': permissions, 'revision': revision, 'time_windows': self._time_windows(doc, agent_id)}

    def save(self, agent_id, permissions, revision, *, acknowledge_time_windows=False):
        agent = self._agent(agent_id)
        if agent['status'] != 'active':
            raise ValueError('Only active agents can have their permissions changed.')
        if not isinstance(permissions, dict) or set(permissions) != set(RESOURCES):
            raise ValueError('Choose access for all three Gmail operations.')
        for resource, value in permissions.items():
            choices = ('ask', 'deny') if resource == 'gmail:send' else ('allow', 'ask', 'deny')
            if not isinstance(value, str) or value not in choices:
                raise ValueError('Invalid permission selection. Sending must require approval or be denied.')
        doc, current_revision = self._snapshot()
        if not isinstance(revision, str) or revision != current_revision:
            raise PermissionConflict('Permissions changed elsewhere. Reload and review before saving.')
        if self._time_windows(doc, agent_id) and acknowledge_time_windows is not True:
            raise ValueError('Explicitly acknowledge replacing existing time windows with all-time rules.')
        managed = [{'name': f'{MARKER}:{agent_id}:{resource}', 'managed_by': MARKER,
                    'agent': agent_id, 'credential': resource,
                    'auto_approve': value == 'allow', 'escalate': value == 'ask'}
                   for resource, value in permissions.items()]
        retained = [rule for rule in doc['policies'] if not (rule.get('managed_by') == MARKER and rule.get('agent') == agent_id)]
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
        return self.view(agent_id)
