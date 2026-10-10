from __future__ import annotations

import asyncio
import datetime
import secrets
from collections import deque
from dataclasses import dataclass, field


def issue_token(ttl_minutes: int, now: datetime.datetime | None = None) -> tuple[str, str]:
    if now is None:
        now = datetime.datetime.now()
    token = secrets.token_urlsafe(32)
    expiry = (now + datetime.timedelta(minutes=ttl_minutes)).isoformat(timespec="seconds")
    return token, expiry


@dataclass
class PendingRequest:
    agent: str
    credential: str
    details: str | None = None
    request_id: str = field(default_factory=lambda: secrets.token_urlsafe(16))
    approval_code: str = field(default_factory=lambda: secrets.token_hex(3))
    future: "asyncio.Future[bool] | None" = field(default=None)  # set in submit


class ApprovalQueue:
    def __init__(self) -> None:
        self._queue: deque[PendingRequest] = deque()

    async def submit(
        self, agent: str, credential: str, timeout: float | None = None,
        details: str | None = None
    ) -> bool:
        loop = asyncio.get_running_loop()
        req = PendingRequest(agent=agent, credential=credential, details=details, future=loop.create_future())
        self._queue.append(req)
        try:
            if timeout is None:
                return await req.future
            return await asyncio.wait_for(req.future, timeout)
        finally:
            self._remove(req)

    def get_pending(self) -> PendingRequest | None:
        for req in self._queue:
            if not req.future.done():
                return req
        return None

    def _remove(self, request: PendingRequest) -> None:
        try:
            self._queue.remove(request)
        except ValueError:
            pass

    def resolve(self, request: PendingRequest, approved: bool) -> None:
        if not request.future.done():
            request.future.set_result(approved)
        self._remove(request)

    def pending_count(self) -> int:
        return sum(1 for r in self._queue if not r.future.done())
