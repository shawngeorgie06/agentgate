from __future__ import annotations

import re

_ALLOWED_VERBS = {"SELECT", "INSERT", "UPDATE", "DELETE"}
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")


class GrantError(Exception):
    """Raised when a grant definition is malformed or uses a disallowed verb/identifier."""


def validate_grant(raw: dict) -> dict:
    verb = str(raw.get("verb", "")).upper()
    if verb not in _ALLOWED_VERBS:
        raise GrantError(f"grant verb must be one of {sorted(_ALLOWED_VERBS)}, got {verb!r}")
    objects = raw.get("objects") or []
    if not objects:
        raise GrantError("grant must name at least one object")
    normalized: list[str] = []
    for obj in objects:
        parts = str(obj).split(".")
        if len(parts) not in (1, 2) or not all(_IDENT.match(p) for p in parts):
            raise GrantError(f"invalid object identifier {obj!r}")
        normalized.append(".".join(parts))
    return {"verb": verb, "objects": normalized}


def quote_ident(obj: str) -> str:
    # Callers must have validated obj against _IDENT already; parts cannot
    # contain a double quote, so wrapping is safe.
    return ".".join(f'"{part}"' for part in obj.split("."))


def build_grant_statements(role: str, grants: list[dict]) -> list[str]:
    statements = []
    for grant in grants:
        objects = ", ".join(quote_ident(o) for o in grant["objects"])
        statements.append(f'GRANT {grant["verb"]} ON {objects} TO "{role}"')
    return statements
