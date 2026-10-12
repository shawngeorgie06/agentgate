"""Local operator app. Its credential is deliberately separate from agent MCP auth."""
from __future__ import annotations

import asyncio
import json
import logging
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
from broker.connections import GmailConnection
from broker.credential_store import CredentialDecryptionError
from broker.gmail_tools import GmailTools
from broker.integrations.gmail import GmailError, TOKEN_NAME
from broker.integrations.github import GitHub, GitHubError
from broker.grants_dashboard import create_grant, get_grants, revoke_grant
from broker.grants import GrantError
from broker.permissions import Permissions, PermissionConflict
from broker.policy_engine import PolicyError

ASSETS = Path(__file__).with_name('web')
# POST action -> broker.imessage_service method. 'imessage-pair' takes an agent_id instead.
IMESSAGE_MUTATIONS = {
    'imessage-pair': 'start_pairing',
    'imessage-pair-cancel': 'cancel_pairing',
    'imessage-enable': 'enable',
    'imessage-disable': 'disable',
    'imessage-unpair': 'unpair',
}


def _imessage_unavailable():
    return {'available': False, 'enabled': False, 'paired': False, 'running': False,
            'agent': None,
            'model': {'available': False, 'reason': 'iMessage is not available on this broker.'},
            'pairing': None, 'recent': [], 'error': None}


async def _settled_to_thread(function, *args):
    """Keep mutation locks until their worker finishes, even if HTTP is canceled."""
    task = asyncio.create_task(asyncio.to_thread(function, *args))
    canceled = False
    while True:
        try:
            result = await asyncio.shield(task)
            break
        except asyncio.CancelledError:
            canceled = True
            continue
        except BaseException:
            if canceled:
                raise asyncio.CancelledError from None
            raise
    if canceled:
        raise asyncio.CancelledError
    return result


def create_dashboard(mcp_app, broker, tools: GmailTools, operator_token: str, *, github=None):
    permissions = Permissions(broker)
    gmail_mutation_lock = asyncio.Lock()
    github_mutation_lock = asyncio.Lock()
    client_file = os.environ.get(
        'GMAIL_CLIENT_PATH',
        str(Path(broker.config.credentials_path).expanduser().parent / 'oauth-client.json'),
    )
    gmail_connection = GmailConnection(broker, tools.gmail, client_file)
    github = github or GitHub(broker.store)

    async def asset(request):
        names = {'app': 'index.html', 'app.js': 'app.js', 'app.css': 'app.css',
                 'connections.js': 'connections.js', 'grants.js': 'grants.js', 'imessage.js': 'imessage.js'}
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
            elif request.method == 'GET' and action == 'connections':
                gmail_info, github_info = await asyncio.gather(
                    asyncio.to_thread(gmail_connection.info),
                    asyncio.to_thread(github.info),
                )
                registry = getattr(broker, 'agent_registry', None)
                active_agents = [agent for agent in registry.list_agents()
                                 if agent.get('status') == 'active'] if registry is not None else []
                grants_store = getattr(broker, 'temporary_grants', None)
                live_grants = grants_store.list_grants() if grants_store is not None else []
                for service_info in (gmail_info, github_info):
                    service = service_info['service']
                    prefix = service + ':'
                    service_agents = []
                    for agent in active_agents:
                        view = permissions.view(agent['id'], service=service)
                        temporary = [
                            {'resource': row['resource'], 'permission': row['permission'],
                             'expires_at': row['expires_at']}
                            for row in live_grants
                            if row.get('status') == 'active'
                            and row.get('agent_id') == agent['id']
                            and row.get('resource', '').startswith(prefix)
                        ]
                        service_agents.append({
                            'id': agent['id'], 'name': agent['name'],
                            'permissions': view['permissions'],
                            'temporary_grants': temporary,
                        })
                    service_info['agents'] = service_agents
                data = {'services': [gmail_info, github_info]}
            elif request.method == 'GET' and action == 'reconnect-status':
                data = gmail_connection.reconnect_status()
            elif request.method == 'GET' and action == 'grants':
                data = get_grants(broker)
            elif request.method == 'GET' and action == 'imessage':
                service = getattr(broker, 'imessage_service', None)
                data = await service.snapshot() if service is not None else _imessage_unavailable()
            elif request.method == 'GET' and action == 'permissions':
                data = permissions.view(request.query_params.get('agent_id', ''),
                                        service=request.query_params.get('service', 'gmail'))
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
                if action == 'connection-disconnect':
                    service = payload.get('service')
                    if service not in ('gmail', 'github'):
                        raise ValueError()
                    if service == 'gmail':
                        async with gmail_mutation_lock:
                            # Gate queued provider calls before canceling approvals
                            # and deleting credentials in a worker.
                            tools.gmail._suspended = True
                            broker.invalidate_agent_requests()
                            try:
                                await _settled_to_thread(gmail_connection.disconnect)
                            finally:
                                broker.invalidate_agent_requests()
                    else:
                        async with github_mutation_lock:
                            github._suspended = True
                            broker.invalidate_agent_requests()
                            try:
                                await _settled_to_thread(github.disconnect)
                            finally:
                                broker.invalidate_agent_requests()
                    data = {'service': service, 'status': 'disconnected'}
                elif action == 'gmail-reconnect':
                    async with gmail_mutation_lock:
                        broker.invalidate_agent_requests()
                        try:
                            data = gmail_connection.begin_reconnect()
                        finally:
                            broker.invalidate_agent_requests()
                elif action == 'github-connect':
                    token = payload.get('token')
                    if not isinstance(token, str):
                        raise ValueError()
                    async with github_mutation_lock:
                        old_suspended = github._suspended
                        github._suspended = True
                        broker.invalidate_agent_requests()
                        try:
                            account = await _settled_to_thread(github.connect, token)
                        except GitHubError:
                            github._suspended = old_suspended
                            raise GitHubError('GitHub could not validate the supplied token.') from None
                        except asyncio.CancelledError:
                            if github._suspended:
                                github._suspended = old_suspended
                            raise
                        except BaseException:
                            # A rejected candidate must leave a working old token usable.
                            github._suspended = old_suspended
                            raise
                        finally:
                            broker.invalidate_agent_requests()
                    safe_account = {}
                    if isinstance(account, dict):
                        if isinstance(account.get('login'), str):
                            safe_account['login'] = account['login']
                        if type(account.get('id')) is int:
                            safe_account['id'] = account['id']
                    data = {'service': 'github', 'status': 'connected', 'account': safe_account}
                elif action == 'grant-create':
                    data = create_grant(broker, payload)
                    tools.audit('operator', 'temporary-access', 'grant-create',
                                state.read_mode(broker.config.state_path), 'completed')
                elif action == 'grant-revoke':
                    data = revoke_grant(broker, payload)
                    tools.audit('operator', 'temporary-access', 'grant-revoke',
                                state.read_mode(broker.config.state_path), 'completed')
                elif action == 'approval':
                    pending = broker.approvals.get_pending()
                    if not pending or payload.get('id') != pending.request_id:
                        return JSONResponse({'ok': False, 'reason': 'This approval expired or changed. Refresh and review the current request.'}, status_code=409, headers=headers)
                    if type(payload.get('approved')) is not bool:
                        raise ValueError()
                    broker.approvals.resolve(pending, payload['approved'])
                    data = {'approved': payload['approved']}
                elif action == 'permissions':
                    agent_id = payload.get('agent_id')
                    if not isinstance(agent_id, str):
                        raise ValueError()
                    try:
                        data = permissions.save(agent_id, payload.get('permissions'), payload.get('revision'),
                                                acknowledge_time_windows=payload.get('acknowledge_time_windows', False),
                                                service=payload.get('service', 'gmail'))
                    except Exception:
                        tools.audit('operator', 'permissions:update', 'operator-settings', state.read_mode(broker.config.state_path), 'failed')
                        raise
                    tools.audit('operator', 'permissions:update', agent_id, state.read_mode(broker.config.state_path), 'completed')
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
                elif action in IMESSAGE_MUTATIONS:
                    if action == 'imessage-pair':
                        agent_id = payload.get('agent_id')
                        if not isinstance(agent_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', agent_id):
                            raise ValueError()
                    service = getattr(broker, 'imessage_service', None)
                    if service is None:
                        return JSONResponse({'ok': False, 'reason': 'iMessage is unavailable on this broker.'}, status_code=503, headers=headers)
                    if action == 'imessage-pair':
                        try:
                            data = await service.start_pairing(agent_id)
                        except ValueError:
                            return JSONResponse({'ok': False, 'reason': 'Choose an active enrolled agent to pair with iMessage.'}, status_code=400, headers=headers)
                    else:
                        data = await getattr(service, IMESSAGE_MUTATIONS[action])()
                elif action == 'mode':
                    data = {'mode': state.toggle_mode(broker.config.state_path)}
                    broker.invalidate_agent_requests()
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
        except CredentialDecryptionError:
            return JSONResponse({'ok': False, 'code': 'credentials_locked',
                                 'reason': 'Saved credentials could not be unlocked. Restart AgentGate and enter the original master password privately. If it is correct, the credential file may be damaged.'},
                                status_code=503, headers=headers)
        except PermissionConflict as exc:
            return JSONResponse({'ok': False, 'reason': str(exc)}, status_code=409, headers=headers)
        except PolicyError:
            return JSONResponse({'ok': False, 'reason': 'The policy file is invalid. Repair it before editing permissions.'}, status_code=400, headers=headers)
        except (GmailError, GitHubError) as exc:
            return JSONResponse({'ok': False, 'reason': str(exc)}, status_code=400, headers=headers)
        except GrantError as exc:
            return JSONResponse({'ok': False, 'reason': str(exc)}, status_code=400, headers=headers)
        except (ValueError, TypeError):
            return JSONResponse({'ok': False, 'reason': 'Invalid request.'}, status_code=400, headers=headers)
        except Exception as exc:
            # Exception text and tracebacks may contain credentials or mail.
            logging.getLogger(__name__).error('Operator API failed (%s).', type(exc).__name__)
            return JSONResponse({'ok': False, 'reason': 'Operation failed. Check the connection and try refreshing.'}, status_code=500, headers=headers)

    @asynccontextmanager
    async def lifespan(app):
        try:
            async with mcp_app.router.lifespan_context(mcp_app):
                yield
        finally:
            await gmail_connection.close()

    return Starlette(routes=[Route('/app', asset), Route('/app/{asset}', asset),
                             Route('/api/{action}', api, methods=['GET', 'POST']), Mount('/', mcp_app)],
                     lifespan=lifespan, middleware=[Middleware(HostOriginGuardMiddleware,
                         allowed_hosts=['127.0.0.1', 'localhost'], allowed_origins=[], mode='strict')])
