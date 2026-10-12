"""Bounded stdin transport to Apple's local Foundation Models helper."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess

from broker.helper_env import minimal_helper_env

ACTIONS = frozenset({'chat', 'unsupported', 'gmail_unread', 'gmail_search', 'gmail_read',
                     'github_repos', 'github_issues', 'github_file'})
PLAN_FIELDS = frozenset({'action', 'query', 'message_id', 'owner', 'repo', 'path', 'ref'})
ERRORS = {
    'model_unavailable': 'Apple Intelligence is unavailable. Enable it in System Settings.',
    'model_timeout': 'The local model took too long. Try a shorter request.',
    'model_failed': 'The local model could not complete this request.',
    'invalid_input': 'The request exceeds the local model limits or is invalid.',
    'unsafe_helper': 'The local model helper is missing or is not safely installed.',
}


def _error(code):
    return {'ok': False, 'reason': ERRORS[code], 'code': code}


class AppleModel:
    def __init__(self, helper_path):
        self.helper_path = Path(helper_path).expanduser().absolute()

    def availability(self):
        return self._call({'mode': 'availability'})

    def plan(self, prompt, history=''):
        return self._call({'mode': 'plan', 'prompt': prompt, 'history': history})

    def answer(self, prompt, context, history=''):
        return self._call({'mode': 'answer', 'prompt': prompt, 'context': context, 'history': history})

    def _call(self, request):
        mode = request['mode']
        for field, limit in [('prompt', 2000), ('history', 4000), ('context', 6000)]:
            if field in request:
                value = request[field]
                if not isinstance(value, str) or len(value) > limit or '\x00' in value:
                    return _error('invalid_input')
        if mode != 'availability' and not request['prompt'].strip():
            return _error('invalid_input')
        try:
            info = self.helper_path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o022 or not info.st_mode & 0o100):
                return _error('unsafe_helper')
        except OSError:
            return _error('unsafe_helper')
        try:
            result = subprocess.run([str(self.helper_path)], input=json.dumps(request).encode(),
                                    capture_output=True, timeout=60, check=False,
                                    env=minimal_helper_env(), cwd='/')
            if result.returncode or not 0 < len(result.stdout) <= 65536:
                return _error('model_failed')
            output = json.loads(result.stdout)
            if not isinstance(output, dict) or type(output.get('ok')) is not bool:
                return _error('model_failed')
            if not output['ok']:
                code = output.get('code')
                return _error(code if code in ERRORS else 'model_failed')
            if set(output) != {'ok', 'data'} or not isinstance(output['data'], dict):
                return _error('model_failed')
            data = output['data']
            if mode == 'plan':
                if (set(data) != PLAN_FIELDS or data.get('action') not in ACTIONS
                        or any(not isinstance(v, str) or len(v) > 2000 or '\x00' in v for v in data.values())):
                    return _error('model_failed')
            elif mode == 'answer':
                text = data.get('text')
                if (set(data) != {'text'} or not isinstance(text, str) or not 0 < len(text) <= 1200
                        or '\x00' in text or text.lstrip().lower().startswith('/agent')):
                    return _error('model_failed')
            elif (set(data) != {'available', 'reason'} or type(data.get('available')) is not bool
                  or not isinstance(data.get('reason'), str) or len(data['reason']) > 200):
                return _error('model_failed')
            return {'ok': True, 'data': data}
        except subprocess.TimeoutExpired:
            return _error('model_timeout')
        except Exception:
            return _error('model_failed')
