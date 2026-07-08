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
        username: str | None = None,
        grants: list[str] | None = None,
        key_id: str | None = None,
        role_arn: str | None = None,
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
        if username is not None:
            entry["username"] = username
        if grants is not None:
            entry["grants"] = list(grants)
        if key_id is not None:
            entry["key_id"] = key_id
        if role_arn is not None:
            entry["role_arn"] = role_arn
        self._append(entry)

    def log_operator(self, *, action: str, subject: str) -> None:
        """Audit an operator-initiated mutation (credential seeded/deleted,
        agent registered/revoked, connection added/removed, mode toggled).
        Subjects are names only — never values or keys."""
        self._append({
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(
                timespec="seconds"
            ),
            "actor": "operator",
            "action": action,
            "subject": subject,
        })

    def _append(self, entry: dict) -> None:
        is_new = not os.path.exists(self._path)
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        if is_new:
            os.chmod(self._path, 0o600)
