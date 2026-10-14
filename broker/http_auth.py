"""Local MCP bearer credentials; Google credentials are never used as client auth."""
from __future__ import annotations

import os
import re
import secrets
import stat
from pathlib import Path
from typing import TYPE_CHECKING

from fastmcp.server.auth.providers.jwt import StaticTokenVerifier, TokenVerifier
from fastmcp.server.auth import AccessToken

from broker.config import ConfigError

if TYPE_CHECKING:
    from broker.agent_registry import AgentRegistry


def create_token_file(path: str) -> None:
    destination = Path(path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='ascii') as stream:
        stream.write(secrets.token_urlsafe(32) + '\n')


def read_token_file(path: str) -> str:
    try:
        fd = os.open(Path(path).expanduser(), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'r', encoding='ascii') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ConfigError('MCP token file must be a regular file owned by you with private permissions (0600).')
            if info.st_size > 513:
                raise ConfigError('MCP token file is too large.')
            token = stream.read(513).strip()
    except (OSError, UnicodeError):
        raise ConfigError('Could not read the private MCP token file.') from None
    if not re.fullmatch(r'[A-Za-z0-9_-]{32,512}', token):
        raise ConfigError('MCP token file must contain a 32–512 character URL-safe token.')
    return token


def token_verifier(path: str) -> StaticTokenVerifier:
    token = read_token_file(path)
    return StaticTokenVerifier(tokens={token: {'client_id': 'agentgate-local', 'scopes': ['agentgate']}})


class RegistryTokenVerifier(TokenVerifier):
    """FastMCP bearer verifier backed by the revocable identity registry."""

    def __init__(self, registry: "AgentRegistry"):
        super().__init__(required_scopes=[])
        self.registry = registry

    async def verify_token(self, token: str) -> AccessToken | None:
        agent = self.registry.authenticate(token)
        if agent is None:
            return None
        return AccessToken(token=token, client_id=agent["id"], scopes=["agentgate"],
                           claims={"agent_id": agent["id"]})
