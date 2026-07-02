from __future__ import annotations

import datetime
import json
import os

_VALID_DECISIONS = {"approved", "denied", "escalated", "expired"}


class AuditLogger:
    def __init__(self, path: str) -> None:
        self._path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def log(
        self,
        *,
        agent: str,
        credential_requested: str,
        policy_matched: str,
        decision: str,
        mode: str,
        token_expiry: str | None,
        scopes: list[str] | None = None,
    ) -> None:
        if decision not in _VALID_DECISIONS:
            raise ValueError(f"decision must be one of {_VALID_DECISIONS}, got {decision!r}")
        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "agent": agent,
            "credential_requested": credential_requested,
            "policy_matched": policy_matched,
            "decision": decision,
            "mode": mode,
            "token_expiry": token_expiry,
        }
        if scopes is not None:
            entry["scopes"] = list(scopes)
        is_new = not os.path.exists(self._path)
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        if is_new:
            os.chmod(self._path, 0o600)
