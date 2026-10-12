import asyncio
import datetime as dt

import pytest

from broker.agent_registry import AgentRegistry
from broker.grants import TemporaryGrants
from tests.test_gmail import make_tools, pending


@pytest.mark.asyncio
async def test_draft_lease_expiry_while_send_approval_waits_blocks_final_send(tmp_path):
    broker, service, _, tools = make_tools(tmp_path)
    registry = AgentRegistry(tmp_path / "agents.sqlite3")
    registry.register("local-agent")
    broker.agent_registry = registry
    now = [dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)]
    broker.temporary_grants = TemporaryGrants(registry, clock=lambda: now[0])
    broker.temporary_grants.create("local-agent", "gmail:draft", "allow", 1)

    task = asyncio.create_task(tools.send_draft("local-agent", "draft-1"))
    request = await pending(broker)
    assert request.credential == "gmail:send"
    now[0] += dt.timedelta(minutes=1)
    broker.approvals.resolve(request, True)

    result = await task
    assert result["ok"] is False
    assert "permissions changed" in result["reason"].lower()
    assert not any(call[1] == "send" for call in service.calls)
