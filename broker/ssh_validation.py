from __future__ import annotations

import re

# Canonical validation for values that end up inside SSH certificates.
#
# This is the SINGLE SOURCE OF TRUTH for the principal pattern and the
# force-command/key_id rules, enforced both at operator input (`ssh-add`)
# and again at the signing sink (broker/ssh_ca.py) — the same
# validate-at-input-AND-sink discipline as db_grants. It lives in a leaf
# module (imports nothing from broker) so the two enforcement points can
# never drift onto divergent rules. ALWAYS match with `.fullmatch` (the
# pattern is deliberately unanchored; `.match` would admit a trailing
# newline).

# POSIX username: lowercase letter or underscore, then up to 31 of
# [a-z0-9_-]. 32 chars total max.
PRINCIPAL_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}")


class SshValidationError(ValueError):
    """Raised when a principal, force-command, or key_id is unsafe."""


def validate_principal(raw: object) -> str:
    if not isinstance(raw, str) or not PRINCIPAL_RE.fullmatch(raw):
        raise SshValidationError(f"invalid principal {raw!r}")
    return raw


def validate_force_command(raw: object) -> str:
    # isprintable() is False for NUL, newline, CR, tab, and all control
    # characters — anything that could smuggle a second directive into the
    # certificate's critical option.
    if not isinstance(raw, str) or not raw or not raw.isprintable():
        raise SshValidationError("force-command must be non-empty printable text")
    return raw


def validate_key_id(raw: object) -> str:
    # key_id is free text that lands in the target server's sshd log lines;
    # keep it one printable line so it cannot forge log entries.
    if not isinstance(raw, str) or not raw or not raw.isprintable():
        raise SshValidationError("key_id must be non-empty printable text")
    return raw


def ssh_key_id(agent: str, resource: str) -> str:
    # The ONE place the certificate key_id is composed. Both the signing sink
    # (broker/mcp_server.py) and revocation (store + CLI) call this so a
    # revoked key_id is byte-identical to the issued one — if they drifted,
    # revocation would silently fail to match. (The role_naming.py lesson.)
    return f"agentgate:{agent}:{resource}"
