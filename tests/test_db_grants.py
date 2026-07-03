from __future__ import annotations

import pytest

from broker import db_grants


def test_validate_accepts_allowed_verb_and_identifiers():
    out = db_grants.validate_grant({"verb": "select", "objects": ["public.events", "users"]})
    assert out == {"verb": "SELECT", "objects": ["public.events", "users"]}


@pytest.mark.parametrize("verb", ["ALL", "DROP", "GRANT", "TRUNCATE", "REFERENCES", ""])
def test_validate_rejects_disallowed_verbs(verb):
    with pytest.raises(db_grants.GrantError):
        db_grants.validate_grant({"verb": verb, "objects": ["t"]})


@pytest.mark.parametrize("obj", [
    'events"; DROP ROLE x --',
    "events; DELETE",
    "a.b.c",
    "has space",
    "1nvalid",
    "back`tick",
    "",
])
def test_validate_rejects_bad_identifiers(obj):
    with pytest.raises(db_grants.GrantError):
        db_grants.validate_grant({"verb": "SELECT", "objects": [obj]})


def test_validate_requires_at_least_one_object():
    with pytest.raises(db_grants.GrantError):
        db_grants.validate_grant({"verb": "SELECT", "objects": []})


def test_quote_ident_qualified_and_bare():
    assert db_grants.quote_ident("events") == '"events"'
    assert db_grants.quote_ident("public.events") == '"public"."events"'


def test_build_grant_statements():
    grants = [
        {"verb": "SELECT", "objects": ["public.events", "users"]},
        {"verb": "INSERT", "objects": ["public.audit"]},
    ]
    stmts = db_grants.build_grant_statements("agentgate_ab12", grants)
    assert stmts == [
        'GRANT SELECT ON "public"."events", "users" TO "agentgate_ab12"',
        'GRANT INSERT ON "public"."audit" TO "agentgate_ab12"',
    ]
