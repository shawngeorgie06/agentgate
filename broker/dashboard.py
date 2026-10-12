"""Local operator app. Its credential is deliberately separate from agent MCP auth."""
from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastmcp.server.http import HostOriginGuardMiddleware
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Mount, Route

from broker import state
from broker.gmail_tools import GmailTools
from broker.integrations.gmail import GmailError, TOKEN_NAME

ASSETS = Path(__file__).with_name('web')


def create_dashboard(mcp_app, broker, tools: GmailTools, operator_token: str):
    async def asset(request):
        names = {'app': 'index.html', 'app.js': 'app.js', 'app.css': 'app.css'}
        name = names.get(request.path_params.get('asset', 'app'))
        if not name:
            return JSONResponse({'ok': False}, status_code=404)
        return FileResponse(ASSETS / name, headers={
            'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            'X-Content-Type-Options': 'nosniff',
        })

    async def api(request):
        headers = {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'}
        supplied = request.headers.get('authorization', '').removeprefix('Bearer ')
        if not secrets.compare_digest(supplied.encode(), operator_token.encode()):
            return JSONResponse({'ok': False, 'reason': 'Open the app from the operator launcher.'}, status_code=401, headers=headers)
        action = request.path_params['action']
        try:
            if request.method == 'GET' and action == 'status':
                pending = broker.approvals.get_pending()
                details = json.loads(pending.details) if pending and pending.details else None
                data = {**broker.status(), 'gmail_connected': TOKEN_NAME in broker.store.list_names(),
                        'demo': tools.gmail._factory is not None,
                        'pending_count': broker.approvals.pending_count(),
                        'pending': {'id': pending.request_id, 'agent': pending.agent,
                                    'credential': pending.credential, 'preview': details} if pending else None}
            elif request.method == 'GET' and action == 'agents':
                registry = getattr(broker, 'agent_registry', None)
                data = {'agents': registry.list_agents() if registry is not None else [],
                        'available': registry is not None}
            elif request.method == 'GET' and action == 'activity':
                def read_activity():
                    path = Path(broker.config.logs_path)
                    if not path.exists():
                        return []
                    # Limit disk work and return only the newest complete records.
                    with path.open('rb') as stream:
                        size = stream.seek(0, 2)
                        stream.seek(max(0, size - 65536))
                        lines = stream.read().splitlines()
                    if size > 65536:
                        lines = lines[1:]
                    rows = []
                    for line in lines[-50:]:
                        try:
                            rows.append(json.loads(line))
                        except (ValueError, UnicodeError):
                            pass
                    return list(reversed(rows))
                data = {'activity': await asyncio.to_thread(read_activity)}
            elif request.method == 'GET' and action in ('inbox', 'read', 'drafts'):
                arguments = {}
                if action == 'inbox':
                    arguments = {'query': request.query_params.get('query', 'in:inbox'), 'page_token': request.query_params.get('page_token')}
                elif action == 'drafts':
                    arguments = {'page_token': request.query_params.get('page_token')}
                elif action == 'read':
                    arguments = {'message_id': request.query_params.get('id', '')}
                data = await asyncio.to_thread(tools.gmail.call, action, **arguments)
                if action == 'drafts':
                    for draft in data['drafts']:
                        draft['attempted'] = draft['id'] in tools._sent_drafts
                tools.audit('operator', 'gmail:read' if action != 'drafts' else 'gmail:draft', action, state.read_mode(broker.config.state_path), 'completed')
            elif request.method == 'POST':
                if int(request.headers.get('content-length', '0')) > 262144:
                    return JSONResponse({'ok': False, 'reason': 'Request too large.'}, status_code=413, headers=headers)
                body = bytearray()
                async for chunk in request.stream():
                    body.extend(chunk)
                    if len(body) > 262144:
                        return JSONResponse({'ok': False, 'reason': 'Request too large.'}, status_code=413, headers=headers)
                payload = json.loads(body)
                if not isinstance(payload, dict):
                    raise ValueError()
                if action == 'approval':
                    pending = broker.approvals.get_pending()
                    if not pending or payload.get('id') != pending.request_id:
                        return JSONResponse({'ok': False, 'reason': 'This approval expired or changed. Refresh and review the current request.'}, status_code=409, headers=headers)
                    if type(payload.get('approved')) is not bool:
                        raise ValueError()
                    broker.approvals.resolve(pending, payload['approved'])
                    data = {'approved': payload['approved']}
                elif action == 'agent-register':
                    name = payload.get('name')
                    ttl_hours = payload.get('ttl_hours', 720)
                    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', name):
                        raise ValueError()
                    if type(ttl_hours) is not int or not 1 <= ttl_hours <= 8760:
                        raise ValueError()
                    registry = getattr(broker, 'agent_registry', None)
                    if registry is None:
                        return JSONResponse({'ok': False, 'reason': 'Agent identity management is unavailable.'}, status_code=503, headers=headers)
                    credentials_path = getattr(broker.config, 'agents_path', None)
                    if not credentials_path:
                        credentials_path = str(Path(broker.config.credentials_path).parent / 'agents.sqlite3')
                    credential_dir = Path(credentials_path).expanduser().parent / 'agent-credentials'
                    credential_path = credential_dir / f'{name}.token'
                    # Fail before creating an identity when a prior credential needs attention.
                    if credential_path.exists():
                        tools.audit('operator', 'agent:register', name, state.read_mode(broker.config.state_path), 'failed')
                        return JSONResponse({'ok': False, 'reason': 'Choose a different agent name; existing identity credentials are not overwritten.'}, status_code=409, headers=headers)
                    created = None
                    try:
                        created = registry.register(name, ttl_hours=ttl_hours)
                        if credential_dir.is_symlink():
                            raise OSError('unsafe credential directory')
                        credential_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                        directory_info = credential_dir.stat()
                        if not credential_dir.is_dir() or directory_info.st_uid != os.getuid():
                            raise OSError('unsafe credential directory')
                        os.chmod(credential_dir, 0o700)
                        fd = os.open(credential_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        try:
                            with os.fdopen(fd, 'w', encoding='ascii') as stream:
                                stream.write(created['token'] + '\n')
                        except Exception:
                            try:
                                credential_path.unlink()
                            except OSError:
                                pass
                            raise
                    except (ValueError, KeyError):
                        tools.audit('operator', 'agent:register', name, state.read_mode(broker.config.state_path), 'failed')
                        return JSONResponse({'ok': False, 'reason': 'That name may already be registered or reserved. Choose a different agent name.'}, status_code=400, headers=headers)
                    except OSError:
                        if created is not None:
                            try:
                                registry.revoke(created['agent']['id'])
                            except Exception:
                                pass
                        tools.audit('operator', 'agent:register', name, state.read_mode(broker.config.state_path), 'failed')
                        return JSONResponse({'ok': False, 'reason': 'Could not save the private credential file. The identity was revoked; check the credential folder before retrying.'}, status_code=500, headers=headers)
                    except Exception:
                        if created is not None:
                            try:
                                registry.revoke(created['agent']['id'])
                            except Exception:
                                pass
                        tools.audit('operator', 'agent:register', name, state.read_mode(broker.config.state_path), 'failed')
                        return JSONResponse({'ok': False, 'reason': 'Could not register this identity. Check the broker state and try again.'}, status_code=500, headers=headers)
                    tools.audit('operator', 'agent:register', name, state.read_mode(broker.config.state_path), 'completed')
                    data = {'agent': created['agent'], 'credential_path': str(credential_path.resolve())}
                elif action == 'agent-revoke':
                    agent_id = payload.get('id')
                    if not isinstance(agent_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', agent_id):
                        raise ValueError()
                    registry = getattr(broker, 'agent_registry', None)
                    if registry is None:
                        return JSONResponse({'ok': False, 'reason': 'Agent identity management is unavailable.'}, status_code=503, headers=headers)
                    found = registry.revoke(agent_id)
                    tools.audit('operator', 'agent:revoke', agent_id, state.read_mode(broker.config.state_path), 'completed' if found else 'failed')
                    if not found:
                        return JSONResponse({'ok': False, 'reason': 'Identity not found.'}, status_code=404, headers=headers)
                    data = {'revoked': True}
                elif action == 'mode':
                    data = {'mode': state.toggle_mode(broker.config.state_path)}
                elif action == 'draft':
                    allowed = ('to', 'subject', 'body', 'cc', 'bcc')
                    if any(not isinstance(payload.get(k, ''), str) for k in allowed):
                        raise ValueError()
                    data = await asyncio.to_thread(tools.gmail.call, 'draft', **{k: payload.get(k, '') for k in allowed})
                    tools.audit('operator', 'gmail:draft', 'draft', state.read_mode(broker.config.state_path), 'completed')
                elif action == 'send':
                    if not isinstance(payload.get('draft_id'), str):
                        raise ValueError()
                    result = await tools.send_draft('operator', payload['draft_id'], trusted_operator=True)
                    return JSONResponse(result, headers=headers)
                else:
                    return JSONResponse({'ok': False, 'reason': 'Unknown operation.'}, status_code=404, headers=headers)
            else:
                return JSONResponse({'ok': False, 'reason': 'Unknown operation.'}, status_code=404, headers=headers)
            return JSONResponse({'ok': True, 'data': data}, headers=headers)
        except GmailError as exc:
            return JSONResponse({'ok': False, 'reason': str(exc)}, status_code=400, headers=headers)
        except (ValueError, TypeError):
            return JSONResponse({'ok': False, 'reason': 'Invalid request.'}, status_code=400, headers=headers)
        except Exception:
            return JSONResponse({'ok': False, 'reason': 'Operation failed. Check the connection and try refreshing.'}, status_code=500, headers=headers)

    @asynccontextmanager
    async def lifespan(app):
        async with mcp_app.router.lifespan_context(mcp_app):
            yield

    return Starlette(routes=[Route('/app', asset), Route('/app/{asset}', asset),
                             Route('/api/{action}', api, methods=['GET', 'POST']), Mount('/', mcp_app)],
                     lifespan=lifespan, middleware=[Middleware(HostOriginGuardMiddleware,
                         allowed_hosts=['127.0.0.1', 'localhost'], allowed_origins=[], mode='strict')])
