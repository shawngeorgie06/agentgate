from __future__ import annotations

import argparse
import getpass
import os
import sys

from broker import state
from broker.config import Config, ConfigError
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
        value = os.environ.get("AGENTGATE_CRED_VALUE") or sys.stdin.readline().rstrip("\n")
        CredentialStore(config.credentials_path, _password(master_password)).store(args.name, value)
        print(f"stored credential '{args.name}'")
        return 0

    if args.command == "cred-delete":
        try:
            CredentialStore(config.credentials_path, _password(master_password)).delete(args.name)
        except KeyError:
            print(f"no such credential '{args.name}'", file=sys.stderr)
            return 1
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

    return 2


def main() -> None:
    raise SystemExit(run(sys.argv[1:]))


if __name__ == "__main__":
    main()
