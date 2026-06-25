from __future__ import annotations

import asyncio
import datetime
import secrets
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Optional, Tuple


def issue_token(ttl_minutes: int, now: Optional[datetime.datetime] = None) -> Tuple[str, str]:
    if now is None:
        now = datetime.datetime.now()
    token = secrets.token_urlsafe(32)
    expiry = (now + datetime.timedelta(minutes=ttl_minutes)).isoformat(timespec="seconds")
    return token, expiry


@dataclass
class PendingRequest:
    agent: str
    credential: str
    future: "asyncio.Future[bool]" = field(default=None)  # set in submit


class ApprovalQueue:
    def __init__(self) -> None:
        self._queue: Deque[PendingRequest] = deque()

    async def submit(self, agent: str, credential: str) -> bool:
        loop = asyncio.get_running_loop()
        req = PendingRequest(agent=agent, credential=credential, future=loop.create_future())
        self._queue.append(req)
        return await req.future

    def get_pending(self) -> Optional[PendingRequest]:
        for req in self._queue:
            if not req.future.done():
                return req
        return None

    def resolve(self, request: PendingRequest, approved: bool) -> None:
        if not request.future.done():
            request.future.set_result(approved)
        try:
            self._queue.remove(request)
        except ValueError:
            pass

    def pending_count(self) -> int:
        return sum(1 for r in self._queue if not r.future.done())
