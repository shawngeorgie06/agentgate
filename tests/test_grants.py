import datetime as dt

import pytest

from broker.agent_registry import AgentRegistry
from broker.grants import GrantError, TemporaryGrants


class Clock:
    def __init__(self):
        self.value = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)

    def __call__(self):
        return self.value


def setup(tmp_path):
    registry = AgentRegistry(tmp_path / "agents.sqlite3")
    registry.register("worker")
    clock = Clock()
    return registry, clock, TemporaryGrants(registry, clock=clock)


def test_grant_persists_and_expiry_is_live(tmp_path):
    registry, clock, grants = setup(tmp_path)
    grant = grants.create("worker", "gmail:read", "allow", 1, "incident review")

    assert grant["id"]
    assert grant["agent_id"] == "worker"
    assert grant["resource"] == "gmail:read"
    assert grant["permission"] == "allow"
    assert grant["created_at"].endswith("Z")
    assert grant["expires_at"] == "2026-01-01T00:01:00Z"
    assert grants.active_grant("worker", "gmail:read")["id"] == grant["id"]
    assert "token" not in grant and "bearer" not in str(grant).lower()

    reopened = TemporaryGrants(registry, clock=clock)
    assert reopened.active_grant("worker", "gmail:read")["id"] == grant["id"]
    clock.value += dt.timedelta(minutes=1)
    assert reopened.active_grant("worker", "gmail:read") is None
    assert reopened.list_grants()[0]["status"] == "expired"


def test_only_one_live_grant_until_revoked_and_history_remains(tmp_path):
    _, _, grants = setup(tmp_path)
    first = grants.create("worker", "gmail:draft", "ask", 5)
    with pytest.raises(GrantError):
        grants.create("worker", "gmail:draft", "allow", 5)
    assert grants.revoke(first["id"])
    assert not grants.revoke("missing")
    second = grants.create("worker", "gmail:draft", "allow", 5)
    assert second["id"] != first["id"]
    assert [g["status"] for g in grants.list_grants()] == ["revoked", "active"]


@pytest.mark.parametrize("args", [
    ("missing", "gmail:read", "allow", 1, ""),
    ("worker", "gmail:send", "allow", 1, ""),
    ("worker", "gmail:read", "yes", 1, ""),
    ("worker", "gmail:read", "allow", 0, ""),
    ("worker", "gmail:read", "allow", True, ""),
    ("worker", "github:write", "allow", 1, ""),
    ("worker", "gmail:read", "allow", 1, "x" * 501),
])
def test_rejects_invalid_grant_requests(tmp_path, args):
    _, _, grants = setup(tmp_path)
    with pytest.raises(GrantError):
        grants.create(*args)


def test_inactive_agent_grant_never_effective_and_grants_do_not_change_yaml(tmp_path):
    registry, _, grants = setup(tmp_path)
    policy_file = tmp_path / "policies.yaml"
    policy_file.write_text("baseline: ask\n")
    before = policy_file.read_bytes()
    grant = grants.create("worker", "gmail:read", "allow", 5)
    registry.revoke("worker")
    assert grants.active_grant("worker", "gmail:read") is None
    assert grants.list_grants()[0]["id"] == grant["id"]
    assert policy_file.read_bytes() == before
