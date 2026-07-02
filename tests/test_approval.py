import asyncio
import pytest
from broker.approval import ApprovalQueue


@pytest.mark.asyncio
async def test_submit_resolves_when_approved():
    q = ApprovalQueue()
    task = asyncio.create_task(q.submit("claude-code", "anthropic-api-key"))
    await asyncio.sleep(0)  # let submit enqueue
    pending = q.get_pending()
    assert pending is not None
    assert q.pending_count() == 1
    q.resolve(pending, True)
    assert await task is True
    assert q.pending_count() == 0


@pytest.mark.asyncio
async def test_submit_resolves_when_denied():
    q = ApprovalQueue()
    task = asyncio.create_task(q.submit("a", "k"))
    await asyncio.sleep(0)
    q.resolve(q.get_pending(), False)
    assert await task is False


@pytest.mark.asyncio
async def test_submit_times_out_and_removes_request():
    q = ApprovalQueue()
    with pytest.raises(asyncio.TimeoutError):
        await q.submit("claude-code", "anthropic-api-key", timeout=0.01)
    assert q.pending_count() == 0


@pytest.mark.asyncio
async def test_submit_with_timeout_resolved_in_time_returns_value():
    q = ApprovalQueue()
    task = asyncio.create_task(q.submit("a", "k", timeout=5))
    await asyncio.sleep(0)
    pending = q.get_pending()
    assert pending is not None
    q.resolve(pending, True)
    assert await task is True
    assert q.pending_count() == 0
