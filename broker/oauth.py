from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlencode


class OAuthError(Exception):
    """Raised on OAuth protocol or configuration errors."""


@dataclass(frozen=True)
class ProviderPreset:
    auth_url: str
    token_url: str
    revoke_url: str | None
    default_scopes: list[str]
    extra_auth_params: dict[str, str] = field(default_factory=dict)


PRESETS: dict[str, ProviderPreset] = {
    "google": ProviderPreset(
        auth_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        revoke_url="https://oauth2.googleapis.com/revoke",
        default_scopes=["openid", "email", "profile"],
        extra_auth_params={"access_type": "offline", "prompt": "consent"},
    ),
    "github": ProviderPreset(
        auth_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        revoke_url=None,
        default_scopes=["read:user"],
    ),
}


def get_preset(provider: str) -> ProviderPreset:
    try:
        return PRESETS[provider]
    except KeyError:
        raise OAuthError(f"unknown provider '{provider}'; known: {sorted(PRESETS)}") from None


def generate_pkce() -> tuple[str, str]:
    # 64 random bytes -> 86-char base64url string; well within RFC 7636 [43, 128]
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def build_auth_url(
    *,
    preset: ProviderPreset,
    client_id: str,
    redirect_uri: str,
    scopes: list[str],
    state: str,
    challenge: str,
) -> str:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    params.update(preset.extra_auth_params)
    return f"{preset.auth_url}?{urlencode(params)}"
