from __future__ import annotations

import re

_ALLOWED_VERBS = {"SELECT", "INSERT", "UPDATE", "DELETE"}
# No ^/$ anchors: identifier checks use _IDENT.fullmatch(), which anchors both
# ends of the whole string. A plain $ matches *before* a trailing newline, so
# "events\n" would slip past .match()/$ and flow into emitted SQL; fullmatch on
# an unanchored pattern rejects it because the "\n" is left unconsumed.
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*")


class GrantError(Exception):
    """Raised when a grant definition is malformed or uses a disallowed verb/identifier."""


def _is_valid_ident(obj: str) -> bool:
    """Return True iff obj is a safe 1-2 part identifier (each part matches _IDENT)."""
    parts = str(obj).split(".")
    return len(parts) in (1, 2) and all(_IDENT.fullmatch(p) for p in parts)


def validate_grant(raw: dict) -> dict:
    verb = str(raw.get("verb", "")).upper()
    if verb not in _ALLOWED_VERBS:
        raise GrantError(f"grant verb must be one of {sorted(_ALLOWED_VERBS)}, got {verb!r}")
    objects = raw.get("objects") or []
    # Reject non-list/tuple objects: a bare string like "users" would otherwise
    # iterate character-by-character rather than as a single identifier.
    if not isinstance(objects, (list, tuple)):
        raise GrantError(f"grant objects must be a list, got {type(objects).__name__}")
    if not objects:
        raise GrantError("grant must name at least one object")
    normalized: list[str] = []
    for obj in objects:
        if not _is_valid_ident(obj):
            raise GrantError(f"invalid object identifier {obj!r}")
        normalized.append(str(obj))
    return {"verb": verb, "objects": normalized}


def quote_ident(obj: str) -> str:
    # Do not trust the caller: re-validate every dotted part before wrapping.
    # Parts that pass _IDENT cannot contain a double quote, so wrapping is safe;
    # anything else raises rather than emitting unsafe SQL.
    if not _is_valid_ident(obj):
        raise GrantError(f"invalid object identifier {obj!r}")
    return ".".join(f'"{part}"' for part in str(obj).split("."))


def build_grant_statements(role: str, grants: list[dict]) -> list[str]:
    # Defensive re-validation at the SQL-emitting sink: even if a caller skips
    # validate_grant, this must never interpolate an unchecked role, verb, or
    # object into the returned SQL.
    if not _IDENT.fullmatch(str(role)):
        raise GrantError(f"invalid role identifier {role!r}")
    statements = []
    for grant in grants:
        verb = grant["verb"]
        if verb not in _ALLOWED_VERBS:
            raise GrantError(f"grant verb must be one of {sorted(_ALLOWED_VERBS)}, got {verb!r}")
        # quote_ident re-validates every object part and raises on anything unsafe.
        objects = ", ".join(quote_ident(o) for o in grant["objects"])
        statements.append(f'GRANT {verb} ON {objects} TO "{role}"')
    return statements
