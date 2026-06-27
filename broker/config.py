from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

_DEFAULTS = {
    "POLICIES_PATH": os.path.join("policies", "policies.yaml"),
    "STATE_PATH": os.path.join("state", "mode.json"),
    "LOGS_PATH": os.path.join("logs", "audit.log"),
    "CREDENTIALS_PATH": os.path.join("data", "credentials.json"),
    "CONNECTIONS_PATH": os.path.join("data", "connections.json"),
    "OAUTH_REDIRECT_PORT": "8765",
    "TOKEN_TTL_MINUTES": "60",
    "ESCALATION_TIMEOUT_SECONDS": "0",
}


class ConfigError(ValueError):
    """Raised when an environment value is missing, malformed, or out of range."""


def _require_int(value: str, var: str, minimum: int | None = None) -> int:
    positive = minimum is not None and minimum > 0
    kind = "a positive integer" if positive else "an integer"
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ConfigError(f"{var} must be {kind}, got {value!r}") from None
    if minimum is not None and n < minimum:
        kind = "a positive integer" if positive else f">= {minimum}"
        raise ConfigError(f"{var} must be {kind}, got {value!r}")
    return n


def _require_non_empty(value: str, var: str) -> str:
    if not value:
        raise ConfigError(f"{var} must not be empty")
    return value


@dataclass(frozen=True)
class Config:
    policies_path: str
    state_path: str
    logs_path: str
    credentials_path: str
    token_ttl_minutes: int
    escalation_timeout_seconds: int
    master_password: str | None
    connections_path: str = os.path.join("data", "connections.json")
    oauth_redirect_port: int = 8765

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Config":
        env = os.environ if env is None else env

        def get(key: str) -> str:
            return env.get(key, _DEFAULTS[key])

        return cls(
            policies_path=_require_non_empty(get("POLICIES_PATH"), "POLICIES_PATH"),
            state_path=_require_non_empty(get("STATE_PATH"), "STATE_PATH"),
            logs_path=_require_non_empty(get("LOGS_PATH"), "LOGS_PATH"),
            credentials_path=_require_non_empty(get("CREDENTIALS_PATH"), "CREDENTIALS_PATH"),
            token_ttl_minutes=_require_int(get("TOKEN_TTL_MINUTES"), "TOKEN_TTL_MINUTES", minimum=1),
            escalation_timeout_seconds=max(
                0, _require_int(get("ESCALATION_TIMEOUT_SECONDS"), "ESCALATION_TIMEOUT_SECONDS")
            ),
            master_password=env.get("AGENTGATE_MASTER_PASSWORD"),
            connections_path=_require_non_empty(get("CONNECTIONS_PATH"), "CONNECTIONS_PATH"),
            oauth_redirect_port=_require_int(
                get("OAUTH_REDIRECT_PORT"), "OAUTH_REDIRECT_PORT", minimum=1
            ),
        )
