import datetime as dt

from broker.agent_registry import AgentRegistry
from broker.imessage_state import MessageLedger

NOW = dt.datetime(2026, 10, 12, tzinfo=dt.timezone.utc)


def test_baseline_deduplication_persistence_and_private_metadata(tmp_path):
    registry = AgentRegistry(tmp_path / 'agents.sqlite3')
    ledger = MessageLedger(registry)
    base = ledger.baseline('private-chat', 'private-db', NOW, tail_rowid=10)
    assert not ledger.claim('private-chat', 'old', NOW, 11)
    assert not ledger.claim('private-chat', 'old-row', NOW + dt.timedelta(seconds=1), 10)
    assert ledger.claim('private-chat', 'private-message', NOW + dt.timedelta(seconds=1), 11,
                        revision=base['revision'], database_id='private-db')
    assert not MessageLedger(registry).claim('private-chat', 'private-message', NOW + dt.timedelta(seconds=1), 11)
    ledger.mark_attempted('private-message')
    ledger.mark_result('private-message', 'sent')
    assert ledger.list_recent()[0]['status'] == 'sent'
    assert 'private-' not in repr(ledger.list_recent())
    assert b'private-chat' not in registry.path.read_bytes()
    assert b'private-message' not in registry.path.read_bytes()
    assert b'private-db' not in registry.path.read_bytes()


def test_rebaseline_rejects_stale_capture_and_keeps_dedupe(tmp_path):
    ledger = MessageLedger(AgentRegistry(tmp_path / 'agents.sqlite3'))
    base = ledger.baseline('chat', 'db1', NOW)
    assert ledger.claim('chat', 'm', NOW + dt.timedelta(seconds=1), 1)
    next_base = ledger.baseline('chat', 'db2', NOW + dt.timedelta(seconds=2), 2)
    assert next_base['revision'] != base['revision']
    assert not ledger.is_database_current('chat', 'db1')
    assert ledger.is_database_current('chat', 'db2')
    assert not ledger.claim('chat', 'm2', NOW + dt.timedelta(seconds=3), 3,
                            revision=base['revision'], database_id='db1')
    assert not ledger.claim('chat', 'm', NOW + dt.timedelta(seconds=3), 3)
    assert ledger.claim('chat', 'm3', NOW + dt.timedelta(seconds=3), 3,
                        revision=next_base['revision'], database_id='db2')


def test_no_baseline_and_invalid_dates_fail_closed(tmp_path):
    ledger = MessageLedger(AgentRegistry(tmp_path / 'agents.sqlite3'))
    assert not ledger.claim('chat', 'm', NOW, 1)
    ledger.baseline('chat', 'db', NOW)
    assert not ledger.claim('chat', 'm', dt.datetime(2026, 10, 13), 1)
    assert not ledger.claim('chat', 'm', NOW + dt.timedelta(seconds=1), True)


def test_key_file_is_private_and_invalid_inputs_fail_closed(tmp_path):
    import os
    import stat

    import pytest

    from broker.imessage_state import MessageLedgerError

    registry = AgentRegistry(tmp_path / 'agents.sqlite3')
    ledger = MessageLedger(registry)
    key_path = tmp_path / 'imessage-ledger.key'
    assert stat.S_IMODE(os.lstat(key_path).st_mode) == 0o600
    assert len(key_path.read_bytes()) == 32
    base = ledger.baseline('chat', 'db', NOW, tail_rowid=5)
    later = NOW + dt.timedelta(seconds=1)
    assert not ledger.claim('chat', 'm', later, 6, revision='wrong')
    assert not ledger.claim('chat', 'm', later, 6, database_id='other-db')
    assert not ledger.claim('chat', 'm', later, 5)
    assert not ledger.claim('chat', None, later, 6)
    assert not ledger.claim('chat', 'm', later, 6.0)
    assert ledger.claim('chat', 'm', later, 6, revision=base['revision'], database_id='db')
    with pytest.raises(MessageLedgerError):
        ledger.mark_result('m', 'unknown')
    assert ledger.mark_attempted('m')
    assert ledger.mark_result('m', 'failed')
    assert not ledger.mark_result('m', 'sent')
    assert [row['status'] for row in ledger.list_recent()] == ['failed']
