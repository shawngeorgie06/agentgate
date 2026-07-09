from __future__ import annotations

from broker.ssh_revocation_store import SshRevocationStore
from broker.ssh_validation import ssh_key_id


def _store(tmp_path):
    return SshRevocationStore(str(tmp_path / "revocations.json"), "pw")


def test_ssh_key_id_is_canonical():
    assert ssh_key_id("claude-code", "web-1") == "agentgate:claude-code:web-1"


def test_revoke_then_is_revoked(tmp_path):
    s = _store(tmp_path)
    kid = ssh_key_id("claude-code", "web-1")
    assert s.is_revoked(kid) is False
    s.revoke(key_id=kid, agent="claude-code", resource="web-1",
             revoked_at="2026-07-08T00:00:00+00:00", reason="compromised")
    assert s.is_revoked(kid) is True


def test_revocation_persists_across_reload(tmp_path):
    kid = ssh_key_id("claude-code", "web-1")
    _store(tmp_path).revoke(key_id=kid, agent="claude-code", resource="web-1",
                            revoked_at="2026-07-08T00:00:00+00:00")
    assert SshRevocationStore(str(tmp_path / "revocations.json"), "pw").is_revoked(kid)


def test_unrevoke_removes_and_reports(tmp_path):
    s = _store(tmp_path)
    kid = ssh_key_id("claude-code", "web-1")
    s.revoke(key_id=kid, agent="claude-code", resource="web-1",
             revoked_at="2026-07-08T00:00:00+00:00")
    assert s.unrevoke(kid) is True
    assert s.is_revoked(kid) is False
    assert s.unrevoke(kid) is False  # already absent


def test_revoked_key_ids_and_list_entries_sorted(tmp_path):
    s = _store(tmp_path)
    s.revoke(key_id=ssh_key_id("a", "z"), agent="a", resource="z",
             revoked_at="2026-07-08T00:00:00+00:00")
    s.revoke(key_id=ssh_key_id("a", "y"), agent="a", resource="y",
             revoked_at="2026-07-08T00:00:01+00:00", reason="oops")
    assert s.revoked_key_ids() == ["agentgate:a:y", "agentgate:a:z"]
    entries = s.list_entries()
    assert [e["key_id"] for e in entries] == ["agentgate:a:y", "agentgate:a:z"]
    assert entries[0]["reason"] == "oops"
    assert entries[1]["reason"] is None


def test_revoked_key_id_not_plaintext_on_disk(tmp_path):
    kid = ssh_key_id("claude-code", "web-1")
    _store(tmp_path).revoke(key_id=kid, agent="claude-code", resource="web-1",
                            revoked_at="2026-07-08T00:00:00+00:00")
    raw = (tmp_path / "revocations.json").read_text()
    assert kid not in raw  # encrypted at rest


def test_entry_index_is_key_dependent(tmp_path):
    # Same key_id under two different master passwords must not collide to the
    # same on-disk index -> a password-less reader can't test membership.
    kid = ssh_key_id("claude-code", "web-1")
    a = SshRevocationStore(str(tmp_path / "a.json"), "pw-a")
    b = SshRevocationStore(str(tmp_path / "b.json"), "pw-b")
    assert a._entry_id(kid) != b._entry_id(kid)
