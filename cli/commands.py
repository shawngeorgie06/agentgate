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
from broker.db_grants import GrantError, validate_grant
from broker.db_resource_store import DbResource, DbResourceStore
from broker.policy_engine import PolicyEngine
from broker.ssh_ca_store import SshCaExistsError, SshCaStore
from broker.ssh_krl import KrlWriteError, SshKeygenKrlWriter
from broker.ssh_resource_store import SshResource, SshResourceStore
from broker.ssh_revocation_store import SshRevocationStore
from broker.ssh_validation import (
    SshValidationError,
    ssh_key_id,
    validate_force_command,
    validate_key_id,
    validate_principal,
)
from broker.aws_key_store import AwsKeyStore
from broker.aws_resource_store import AwsResource, AwsResourceStore
from broker.aws_validation import (
    AwsValidationError,
    validate_external_id,
    validate_region,
    validate_role_arn,
)


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
    da = sub.add_parser("db-add", help="register a PostgreSQL resource")
    da.add_argument("name")
    da.add_argument("--host", required=True)
    da.add_argument("--port", type=int, required=True)
    da.add_argument("--dbname", required=True)
    da.add_argument("--admin-user", required=True, dest="admin_user")
    da.add_argument("--grant", action="append", default=[], dest="grants",
                    help='repeatable, format "VERB:obj[,obj...]"')
    sub.add_parser("db-list", help="list registered DB resources (no secrets)")
    dr = sub.add_parser("db-remove", help="remove a DB resource")
    dr.add_argument("name")
    sub.add_parser("ssh-ca-init", help="create the SSH certificate authority")
    sub.add_parser("ssh-ca-pub", help="print the CA public key line for sshd_config")
    sa = sub.add_parser("ssh-add", help="register an SSH server resource")
    sa.add_argument("name")
    sa.add_argument("--host", required=True)
    sa.add_argument("--port", type=int, required=True)
    sa.add_argument("--principal", required=True, help="login user certificates are pinned to")
    sa.add_argument("--force-command", default=None, dest="force_command",
                    help="restrict certificates to this single command")
    sub.add_parser("ssh-list", help="list registered SSH resources")
    sr = sub.add_parser("ssh-remove", help="remove an SSH resource")
    sr.add_argument("name")
    rv = sub.add_parser("ssh-revoke", help="revoke an agent's certs for a resource")
    rv.add_argument("agent")
    rv.add_argument("resource")
    rv.add_argument("--reason", default=None, help="operator note stored with the revocation")
    ur = sub.add_parser("ssh-unrevoke", help="lift a revocation")
    ur.add_argument("agent")
    ur.add_argument("resource")
    sub.add_parser("ssh-revoke-list", help="list revoked certs (metadata only)")
    kw = sub.add_parser("ssh-krl-write", help="regenerate the KRL file")
    kw.add_argument("path", nargs="?", default=None, help="output path (default: configured ssh_krl_path)")
    ak = sub.add_parser("aws-key-set", help="store the broker's IAM access key (secret not via argv)")
    ak.add_argument("access_key_id")
    aws_add = sub.add_parser("aws-add", help="register an AWS role resource")
    aws_add.add_argument("name")
    aws_add.add_argument("--role-arn", required=True, dest="role_arn")
    aws_add.add_argument("--region", required=True)
    aws_add.add_argument("--external-id", default=None, dest="external_id")
    sub.add_parser("aws-list", help="list registered AWS resources")
    aws_remove = sub.add_parser("aws-remove", help="remove an AWS resource")
    aws_remove.add_argument("name")
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


def validate_principal_free(raw: object) -> str:
    # Agent + resource names embedded into a key_id: must be non-empty
    # printable single-line text (same rule validate_key_id enforces on the
    # composed id). Rejects the newline/control chars that would let a name
    # smuggle a KRL directive.
    if not isinstance(raw, str) or ":" in raw:
        raise SshValidationError("name must not contain ':'")
    validate_key_id(raw)  # printable / non-empty gate
    return raw


def _validate_reason(raw: str | None) -> str | None:
    if raw is None:
        return None
    if not raw.isprintable():
        raise SshValidationError("reason must be printable text")
    return raw


def _regenerate_krl(config: Config, master_password: str | None, out_path: str | None = None) -> str:
    """Load the CA public key + all revoked key_ids and (re)write the KRL.
    Raises KrlWriteError / KeyError on failure; callers decide the exit code."""
    ca = SshCaStore(config.ssh_ca_path, _password(master_password))
    public_line = ca.public_line()  # KeyError if CA not initialized
    revocations = SshRevocationStore(config.ssh_revocations_path, _password(master_password))
    target = out_path or config.ssh_krl_path
    SshKeygenKrlWriter().write_krl(public_line, revocations.revoked_key_ids(), target)
    return target


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
        for w in PolicyEngine.lint_file(config.policies_path):
            print(f"warning: {w}", file=sys.stderr)
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

    if args.command == "db-add":
        admin_password = os.environ.get("AGENTGATE_DB_ADMIN_PASSWORD")
        if not admin_password:
            admin_password = (
                getpass.getpass(f"admin password for '{args.name}': ")
                if sys.stdin.isatty() else sys.stdin.readline().rstrip("\n")
            )
        if not admin_password:
            print("admin password must not be empty", file=sys.stderr)
            return 2
        try:
            grants = [_parse_grant(g) for g in args.grants]
        except GrantError as exc:
            print(f"invalid grant: {exc}", file=sys.stderr)
            return 2
        DbResourceStore(config.db_resources_path, _password(master_password)).store(DbResource(
            name=args.name, host=args.host, port=args.port, dbname=args.dbname,
            admin_user=args.admin_user, admin_password=admin_password, grants=grants,
            created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        ))
        AuditLogger(config.logs_path).log_operator(action="db-add", subject=args.name)
        print(f"registered db resource '{args.name}'")
        return 0

    if args.command == "db-list":
        store = DbResourceStore(config.db_resources_path, _password(master_password))
        for meta in store.list_metadata():
            grants = "; ".join(f'{g["verb"]} {",".join(g["objects"])}' for g in meta["grants"])
            print(f"{meta['name']}  {meta['host']}:{meta['port']}/{meta['dbname']}  [{grants}]")
        return 0

    if args.command == "db-remove":
        store = DbResourceStore(config.db_resources_path, _password(master_password))
        try:
            store.delete(args.name)
        except KeyError:
            print(f"no such db resource '{args.name}'", file=sys.stderr)
            return 1
        AuditLogger(config.logs_path).log_operator(action="db-remove", subject=args.name)
        print(f"removed db resource '{args.name}'")
        return 0

    if args.command == "ssh-ca-init":
        store = SshCaStore(config.ssh_ca_path, _password(master_password))
        try:
            pub = store.initialize()
        except SshCaExistsError:
            print("ssh CA already initialized (refusing to overwrite: every "
                  "enrolled server trusts the existing key)", file=sys.stderr)
            return 1
        AuditLogger(config.logs_path).log_operator(action="ssh-ca-init", subject="ssh-ca")
        print("SSH CA created. Enroll each server by installing this public key,")
        print("then add to /etc/ssh/sshd_config:  TrustedUserCAKeys /etc/ssh/agentgate_ca.pub")
        print(pub)
        return 0

    if args.command == "ssh-ca-pub":
        store = SshCaStore(config.ssh_ca_path, _password(master_password))
        try:
            print(store.public_line())
        except KeyError:
            print("ssh CA not initialized (run ssh-ca-init first)", file=sys.stderr)
            return 1
        return 0

    if args.command == "ssh-add":
        try:
            # The resource name is composed into the SSH key_id
            # ("agentgate:<agent>:<resource>", broker/ssh_validation.py);
            # reject ':' here so every issuable key_id stays revocable.
            resource_name = validate_principal_free(args.name)
            principal = validate_principal(args.principal)
            force_command = (
                validate_force_command(args.force_command)
                if args.force_command is not None else None
            )
        except SshValidationError as exc:
            print(f"invalid ssh resource: {exc}", file=sys.stderr)
            return 2
        SshResourceStore(config.ssh_resources_path, _password(master_password)).store(
            SshResource(
                name=args.name, host=args.host, port=args.port, principal=principal,
                force_command=force_command,
                created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(
                    timespec="seconds"
                ),
            )
        )
        AuditLogger(config.logs_path).log_operator(action="ssh-add", subject=args.name)
        print(f"registered ssh resource '{args.name}'")
        return 0

    if args.command == "ssh-list":
        store = SshResourceStore(config.ssh_resources_path, _password(master_password))
        for meta in store.list_metadata():
            forced = f"  [force-command: {meta['force_command']}]" if meta["force_command"] else ""
            print(f"{meta['name']}  {meta['principal']}@{meta['host']}:{meta['port']}{forced}")
        return 0

    if args.command == "ssh-remove":
        store = SshResourceStore(config.ssh_resources_path, _password(master_password))
        try:
            store.delete(args.name)
        except KeyError:
            print(f"no such ssh resource '{args.name}'", file=sys.stderr)
            return 1
        AuditLogger(config.logs_path).log_operator(action="ssh-remove", subject=args.name)
        print(f"removed ssh resource '{args.name}'")
        return 0

    if args.command == "ssh-revoke":
        try:
            agent = validate_principal_free(args.agent)
            resource = validate_principal_free(args.resource)
            reason = _validate_reason(args.reason)
        except SshValidationError as exc:
            print(f"invalid revocation: {exc}", file=sys.stderr)
            return 2
        key_id = ssh_key_id(agent, resource)
        store = SshRevocationStore(config.ssh_revocations_path, _password(master_password))
        store.revoke(
            key_id=key_id, agent=agent, resource=resource,
            revoked_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            reason=reason,
        )
        AuditLogger(config.logs_path).log_operator(action="ssh-revoke", subject=key_id)
        try:
            path = _regenerate_krl(config, master_password)
        except KeyError:
            print("revoked, but ssh CA not initialized so no KRL was written "
                  "(run ssh-ca-init)", file=sys.stderr)
            return 1
        except KrlWriteError:
            print("revoked, but KRL generation failed; retry with ssh-krl-write",
                  file=sys.stderr)
            return 1
        print(f"revoked {key_id}")
        print(f"KRL written to {path} — deploy it to each server's RevokedKeys")
        return 0

    if args.command == "ssh-unrevoke":
        try:
            agent = validate_principal_free(args.agent)
            resource = validate_principal_free(args.resource)
        except SshValidationError as exc:
            print(f"invalid revocation: {exc}", file=sys.stderr)
            return 2
        key_id = ssh_key_id(agent, resource)
        store = SshRevocationStore(config.ssh_revocations_path, _password(master_password))
        if not store.unrevoke(key_id):
            print(f"{key_id} was not revoked", file=sys.stderr)
            return 1
        AuditLogger(config.logs_path).log_operator(action="ssh-unrevoke", subject=key_id)
        try:
            path = _regenerate_krl(config, master_password)
        except (KeyError, KrlWriteError):
            print("unrevoked, but KRL regeneration failed; retry with ssh-krl-write",
                  file=sys.stderr)
            return 1
        print(f"unrevoked {key_id}; KRL rewritten to {path}")
        return 0

    if args.command == "ssh-revoke-list":
        store = SshRevocationStore(config.ssh_revocations_path, _password(master_password))
        for e in store.list_entries():
            reason = f"  ({e['reason']})" if e["reason"] else ""
            print(f"{e['key_id']}  revoked {e['revoked_at']}{reason}")
        return 0

    if args.command == "ssh-krl-write":
        try:
            path = _regenerate_krl(config, master_password, out_path=args.path)
        except KeyError:
            print("ssh CA not initialized (run ssh-ca-init first)", file=sys.stderr)
            return 1
        except KrlWriteError:
            print("KRL generation failed", file=sys.stderr)
            return 1
        print(f"KRL written to {path}")
        return 0

    if args.command == "aws-key-set":
        secret = os.environ.get("AGENTGATE_AWS_SECRET_KEY")
        if not secret:
            secret = (
                getpass.getpass("AWS secret access key: ")
                if sys.stdin.isatty() else sys.stdin.readline().rstrip("\n")
            )
        if not secret:
            print("AWS secret access key must not be empty", file=sys.stderr)
            return 2
        AwsKeyStore(config.aws_key_path, _password(master_password)).set(
            args.access_key_id, secret
        )
        AuditLogger(config.logs_path).log_operator(
            action="aws-key-set", subject="aws-broker-key"
        )
        print("stored aws broker key")
        return 0

    if args.command == "aws-add":
        try:
            role_arn = validate_role_arn(args.role_arn)
            region = validate_region(args.region)
            external_id = (
                validate_external_id(args.external_id)
                if args.external_id is not None else None
            )
        except AwsValidationError as exc:
            print(f"invalid aws resource: {exc}", file=sys.stderr)
            return 2
        AwsResourceStore(config.aws_resources_path, _password(master_password)).store(
            AwsResource(
                name=args.name, role_arn=role_arn, region=region,
                external_id=external_id,
                created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(
                    timespec="seconds"
                ),
            )
        )
        AuditLogger(config.logs_path).log_operator(action="aws-add", subject=args.name)
        print(f"registered aws resource '{args.name}'")
        return 0

    if args.command == "aws-list":
        store = AwsResourceStore(config.aws_resources_path, _password(master_password))
        for meta in store.list_metadata():
            ext = f"  external-id: {meta['external_id']}" if meta["external_id"] else ""
            print(f"{meta['name']}  {meta['role_arn']}  ({meta['region']}){ext}")
        return 0

    if args.command == "aws-remove":
        store = AwsResourceStore(config.aws_resources_path, _password(master_password))
        try:
            store.delete(args.name)
        except KeyError:
            print(f"no such aws resource '{args.name}'", file=sys.stderr)
            return 1
        AuditLogger(config.logs_path).log_operator(action="aws-remove", subject=args.name)
        print(f"removed aws resource '{args.name}'")
        return 0

    return 2


def _parse_grant(raw: str) -> dict:
    # "VERB:obj[,obj...]" -> validated {"verb", "objects"}.
    verb, _, objs = raw.partition(":")
    objects = [o.strip() for o in objs.split(",") if o.strip()]
    return validate_grant({"verb": verb.strip(), "objects": objects})


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
