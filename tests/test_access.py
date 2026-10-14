import asyncio
import datetime as dt
from types import SimpleNamespace

from broker.access import AccessController, AccessError
from broker.agent_registry import AgentRegistry
from broker.grants import TemporaryGrants
from broker.policy_engine import PolicyEngine


class Clock:
    def __init__(self):
        self.value = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)

    def __call__(self):
        return self.value


class Approvals:
    def __init__(self):
        self.calls = []

    async def submit(self, agent, resource, **kwargs):
        self.calls.append((agent, resource))
        return True


def broker(tmp_path, mode="auto", auto=True):
    registry = AgentRegistry(tmp_path / "agents.sqlite3")
    registry.register("worker")
    clock = Clock()
    grants = TemporaryGrants(registry, clock=clock)
    return SimpleNamespace(
        temporary_grants=grants, policy_revision=1, total_requests=0,
        escalated_requests=0,
        engine=PolicyEngine([{"name": "baseline", "agent": "*", "credential": "*",
                              "auto_approve": auto, "escalate": True}]),
        approvals=Approvals(), config=SimpleNamespace(escalation_timeout_seconds=0,
                                                       state_path=str(tmp_path / "mode.json")),
        audit=SimpleNamespace(log=lambda **kw: None), store=None,
    ), clock


def test_github_write_always_manual_and_baseline_restored_after_grant_expiry(tmp_path, monkeypatch):
    b, clock = broker(tmp_path, auto=True)
    monkeypatch.setattr("broker.access.state.read_mode", lambda _: "auto")
    access = AccessController(b)
    assert asyncio.run(access.authorize("worker", "github:write")) is True
    assert b.approvals.calls == [("worker", "github:write")]
    grant = b.temporary_grants.create("worker", "github:write", "ask", 1)
    clock.value += dt.timedelta(minutes=1)
    assert b.temporary_grants.active_grant("worker", "github:write") is None
    assert asyncio.run(access.authorize("worker", "github:read")) is True


def test_manual_mode_requests_approval_for_baseline_allowed_read(tmp_path, monkeypatch):
    b, _ = broker(tmp_path, auto=True)
    monkeypatch.setattr("broker.access.state.read_mode", lambda _: "manual")
    assert asyncio.run(AccessController(b).authorize("worker", "gmail:read")) is True
    assert b.approvals.calls == [("worker", "gmail:read")]


def test_temporary_allow_lifts_baseline_deny_only_until_expiry(tmp_path, monkeypatch):
    b, clock = broker(tmp_path, auto=False)
    b.engine = PolicyEngine([{"name": "hard-deny", "agent": "*", "credential": "*",
                              "auto_approve": False, "escalate": False}])
    monkeypatch.setattr("broker.access.state.read_mode", lambda _: "auto")
    access = AccessController(b)
    assert asyncio.run(access.authorize("worker", "github:read")) is False
    b.temporary_grants.create("worker", "github:read", "allow", 1)
    assert asyncio.run(access.authorize("worker", "github:read")) is True
    clock.value += dt.timedelta(minutes=1)
    assert asyncio.run(access.authorize("worker", "github:read")) is False


def test_write_lease_with_ask_still_requires_manual_approval_over_baseline_deny(tmp_path, monkeypatch):
    b, _ = broker(tmp_path, auto=False)
    b.engine = PolicyEngine([{"name": "hard-deny", "agent": "*", "credential": "*",
                              "auto_approve": False, "escalate": False}])
    monkeypatch.setattr("broker.access.state.read_mode", lambda _: "auto")
    b.temporary_grants.create("worker", "github:write", "ask", 5)
    assert asyncio.run(AccessController(b).authorize("worker", "github:write")) is True
    assert b.approvals.calls == [("worker", "github:write")]


def test_captured_grant_expiry_blocks_dispatch_even_when_baseline_allows(tmp_path, monkeypatch):
    b, clock = broker(tmp_path, auto=True)
    monkeypatch.setattr("broker.access.state.read_mode", lambda _: "auto")
    b.temporary_grants.create("worker", "github:read", "allow", 1)
    access = AccessController(b)
    guard = access.access_guard("worker", "github:read")
    assert guard()
    clock.value += dt.timedelta(minutes=1)
    assert not guard()


def test_captured_grant_revocation_invalidates_queued_guard(tmp_path, monkeypatch):
    b, _ = broker(tmp_path, auto=True)
    monkeypatch.setattr("broker.access.state.read_mode", lambda _: "auto")
    grant = b.temporary_grants.create("worker", "github:read", "allow", 1)
    guard = AccessController(b).access_guard("worker", "github:read")
    assert guard()
    assert b.temporary_grants.revoke(grant["id"])
    assert not guard()


def test_execute_guard_raises_at_provider_boundary_and_sanitizes_failure(tmp_path, monkeypatch):
    b, clock = broker(tmp_path, auto=True)
    monkeypatch.setattr("broker.access.state.read_mode", lambda _: "auto")
    b.temporary_grants.create("worker", "gmail:read", "ask", 1)
    access = AccessController(b)
    async def approve_then_expire(*args, **kwargs):
        clock.value += dt.timedelta(minutes=1)
        return True
    b.approvals.submit = approve_then_expire

    class Provider:
        def call(self, operation, *, before_dispatch, **arguments):
            before_dispatch()
            raise AssertionError("provider must not dispatch")

    result = asyncio.run(access.execute(Provider(), "worker", "gmail:read", "read", identity_guard=None))
    assert result["ok"] is False
    assert "expired" in result["reason"].lower() or "changed" in result["reason"].lower()


def test_baseline_time_window_change_invalidates_captured_dispatch(tmp_path, monkeypatch):
    b, _ = broker(tmp_path)
    decision = SimpleNamespace(policy_name='window',auto_approve=True,escalate=True)
    b.engine = SimpleNamespace(evaluate=lambda *_:decision)
    guard = AccessController(b).access_guard('worker','github:read')
    assert guard()
    decision.policy_name = 'outside-window'
    decision.auto_approve = False
    decision.escalate = False
    assert not guard()

def test_switching_to_manual_invalidates_auto_authorized_dispatch(tmp_path, monkeypatch):
    b, _ = broker(tmp_path)
    mode = ['auto']
    monkeypatch.setattr('broker.access.state.read_mode', lambda _:mode[0])
    guard = AccessController(b).access_guard('worker','gmail:draft')
    assert guard()
    mode[0] = 'manual'
    assert not guard()
