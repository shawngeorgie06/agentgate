from __future__ import annotations

from broker import db_broker, db_executor, role_naming


def test_both_sql_sinks_share_the_one_canonical_role_pattern():
    # No drift possible: db_broker (build_mint_statements + reap) and
    # db_executor (drop_role) must guard against the exact same object.
    assert db_broker._ROLE_RE is role_naming.ROLE_RE
    assert db_executor._ROLE_RE is role_naming.ROLE_RE
    assert db_broker.ROLE_PREFIX == role_naming.ROLE_PREFIX == "agentgate_"


def test_canonical_pattern_is_fullmatch_safe_against_trailing_newline():
    # The pattern is unanchored on purpose; every sink uses .fullmatch, which
    # rejects a trailing newline (a `$`-anchored .match would have admitted it).
    assert role_naming.ROLE_RE.fullmatch("agentgate_ab12cd34")
    assert not role_naming.ROLE_RE.fullmatch("agentgate_ab12\n")
    assert not role_naming.ROLE_RE.fullmatch('agentgate_ab"; DROP ROLE postgres')
    assert not role_naming.ROLE_RE.fullmatch("postgres")
