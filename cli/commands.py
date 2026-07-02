from __future__ import annotations

import argparse
import asyncio
import datetime
import getpass
import os
import secrets
import sys
import webbrowser

from broker import oauth
from broker import state
from broker.agent_store import AgentStore
from broker.audit import AuditLogger
from broker.config import Config, ConfigError
from broker.connection_store import Connection, ConnectionStore
from broker.credential_store import CredentialStore
from broker.policy_engine import PolicyEngine


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentgate", description="AgentGate operator CLI")
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("cred-store", help="store a credential")
    s.add_argument("name")
    d = sub.add_parser("cred-delete", help="delete a credential")
    d.add_argument("name")
    sub.add_parser("cred-list", help="list credential names")
    sub.add_parser("policy-validate", help="validate the policy file")
    sub.add_parser("status", help="print broker status")
    c = sub.add_parser("connect", help="connect an OAuth provider account")
    c.add_argument("provider")
    c.add_argument("name", nargs="?", default=None)
    sub.add_parser("connections", help="list connected accounts")
    dc = sub.add_parser("disconnect", help="revoke and remove a connection")
    dc.add_argument("name")
    aa = sub.add_parser("agent-add", help="register an agent; prints its key once")
    aa.add_argument("name")
    ar = sub.add_parser("agent-remove", help="revoke an agent's registration")
    ar.add_argument("name")
    sub.add_parser("agent-list", help="list registered agent names")
    return parser


def _password(master_password: str | None) -> str:
    if master_password:
        return master_password
    env = os.environ.get("AGENTGATE_MASTER_PASSWORD")
    if env:
        return env
    return getpass.getpass("AgentGate master password: ")


def run(
    argv: list[str],
    config: Config | None = None,
    master_password: str | None = None,
) -> int:
    if config is None:
        try:
            config = Config.from_env()
        except ConfigError as exc:
            print(f"[AgentGate] configuration error: {exc}", file=sys.stderr)
            return 2
    args = build_parser().parse_args(argv)

    if args.command == "cred-store":
        value = os.environ.get("AGENTGATE_CRED_VALUE")
        if not value:
            if sys.stdin.isatty():
                # Interactive: prompt rather than silently blocking on stdin.
                value = getpass.getpass(f"value for credential '{args.name}': ")
            else:
                value = sys.stdin.readline().rstrip("\n")
        CredentialStore(config.credentials_path, _password(master_password)).store(args.name, value)
        AuditLogger(config.logs_path).log_operator(action="cred-store", subject=args.name)
        print(f"stored credential '{args.name}'")
        return 0

    if args.command == "cred-delete":
        try:
            CredentialStore(config.credentials_path, _password(master_password)).delete(args.name)
        except KeyError:
            print(f"no such credential '{args.name}'", file=sys.stderr)
            return 1
        AuditLogger(config.logs_path).log_operator(action="cred-delete", subject=args.name)
        print(f"deleted credential '{args.name}'")
        return 0

    if args.command == "cred-list":
        names = CredentialStore(config.credentials_path, _password(master_password)).list_names()
        for name in names:
            print(name)
        return 0

    if args.command == "policy-validate":
        errors = PolicyEngine.validate_file(config.policies_path)
        if errors:
            for e in errors:
                print(f"INVALID: {e}", file=sys.stderr)
            return 1
        print("policy file is valid")
        return 0

    if args.command == "status":
        print(f"mode: {state.read_mode(config.state_path)}")
        print(f"policies: {len(PolicyEngine.from_file(config.policies_path).list_policies())}")
        return 0

    if args.command == "connections":
        store = ConnectionStore(config.connections_path, _password(master_password))
        for meta in store.list_metadata():
            print(f"{meta['name']}  provider={meta['provider']}  "
                  f"scopes={','.join(meta['scopes'])}  created={meta['created_at']}")
        return 0

    if args.command == "disconnect":
        store = ConnectionStore(config.connections_path, _password(master_password))
        try:
            conn = store.get(args.name)
        except KeyError:
            print(f"no such connection '{args.name}'", file=sys.stderr)
            return 1
        # Revoke leniently: a failed remote revoke must not block removal of the
        # local record (and must never leave the operator with a traceback).
        try:
            preset = oauth.get_preset(conn.provider)
            if preset.revoke_url:
                asyncio.run(oauth.revoke(revoke_url=preset.revoke_url, token=conn.refresh_token))
        except oauth.OAuthError as exc:
            print(f"warning: provider revoke failed ({exc}); removing local record anyway",
                  file=sys.stderr)
        store.delete(args.name)
        AuditLogger(config.logs_path).log_operator(action="disconnect", subject=args.name)
        print(f"disconnected '{args.name}'")
        return 0

    if args.command == "connect":
        return _run_connect(config, _password(master_password), args.provider, args.name)

    if args.command == "agent-add":
        store = AgentStore(config.agents_path, _password(master_password))
        try:
            agent_key = store.register(args.name)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        AuditLogger(config.logs_path).log_operator(action="agent-add", subject=args.name)
        print(f"registered agent '{args.name}'")
        print("agent key (shown once — configure it on the agent, it is not stored):")
        print(agent_key)
        return 0

    if args.command == "agent-remove":
        store = AgentStore(config.agents_path, _password(master_password))
        try:
            store.delete(args.name)
        except KeyError:
            print(f"no such agent '{args.name}'", file=sys.stderr)
            return 1
        AuditLogger(config.logs_path).log_operator(action="agent-remove", subject=args.name)
        print(f"removed agent '{args.name}'")
        return 0

    if args.command == "agent-list":
        for name in AgentStore(config.agents_path, _password(master_password)).list_names():
            print(name)
        return 0

    return 2


def _run_connect(config: Config, master_password: str, provider: str, name: str | None) -> int:
    name = name or provider
    client_id = os.environ.get("AGENTGATE_OAUTH_CLIENT_ID")
    client_secret = os.environ.get("AGENTGATE_OAUTH_CLIENT_SECRET")
    if not client_id or not client_secret:
        print(f"set AGENTGATE_OAUTH_CLIENT_ID and AGENTGATE_OAUTH_CLIENT_SECRET "
              f"to connect {provider!r}", file=sys.stderr)
        return 2
    try:
        preset = oauth.get_preset(provider)
    except oauth.OAuthError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    redirect_uri = f"http://localhost:{config.oauth_redirect_port}/callback"
    verifier, challenge = oauth.generate_pkce()
    csrf_state = secrets.token_urlsafe(16)
    url = oauth.build_auth_url(
        preset=preset, client_id=client_id, redirect_uri=redirect_uri,
        scopes=preset.default_scopes, state=csrf_state, challenge=challenge,
    )
    print(f"Opening browser to authorize {provider}. Approve access, then return here.")
    webbrowser.open(url)
    code = oauth.run_callback_server(port=config.oauth_redirect_port, expected_state=csrf_state)
    tokens = asyncio.run(oauth.exchange_code(
        token_url=preset.token_url, client_id=client_id, client_secret=client_secret,
        code=code, redirect_uri=redirect_uri, verifier=verifier,
    ))
    if not tokens["refresh_token"]:
        print("provider returned no refresh token; re-consent with offline access",
              file=sys.stderr)
        return 1
    ConnectionStore(config.connections_path, master_password).store(name, Connection(
        provider=provider, client_id=client_id, client_secret=client_secret,
        refresh_token=tokens["refresh_token"],
        scopes=tokens["scopes"] or preset.default_scopes,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    ))
    AuditLogger(config.logs_path).log_operator(action="connect", subject=f"{name} ({provider})")
    print(f"connected '{name}' ({provider})")
    return 0


def main() -> None:
    raise SystemExit(run(sys.argv[1:]))


if __name__ == "__main__":
    main()
