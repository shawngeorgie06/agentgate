from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping, Optional

_DEFAULTS = {
    "POLICIES_PATH": os.path.join("policies", "policies.yaml"),
    "STATE_PATH": os.path.join("state", "mode.json"),
    "LOGS_PATH": os.path.join("logs", "audit.log"),
    "CREDENTIALS_PATH": os.path.join("data", "credentials.json"),
    "TOKEN_TTL_MINUTES": "60",
    "ESCALATION_TIMEOUT_SECONDS": "0",
}


@dataclass(frozen=True)
class Config:
    policies_path: str
    state_path: str
    logs_path: str
    credentials_path: str
    token_ttl_minutes: int
    escalation_timeout_seconds: int
    master_password: Optional[str]

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Config":
        env = os.environ if env is None else env

        def get(key: str) -> str:
            return env.get(key, _DEFAULTS[key])

        return cls(
            policies_path=get("POLICIES_PATH"),
            state_path=get("STATE_PATH"),
            logs_path=get("LOGS_PATH"),
            credentials_path=get("CREDENTIALS_PATH"),
            token_ttl_minutes=int(get("TOKEN_TTL_MINUTES")),
            escalation_timeout_seconds=max(0, int(get("ESCALATION_TIMEOUT_SECONDS"))),
            master_password=env.get("AGENTGATE_MASTER_PASSWORD"),
        )
