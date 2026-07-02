from __future__ import annotations

import base64
import datetime
import hashlib
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse


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


PostForm = Callable[[str, dict], Awaitable[dict]]


async def _default_post_form(url: str, data: dict) -> dict:
    import httpx

    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=data, headers={"Accept": "application/json"})
        if resp.is_error:
            # Sanitize: surface only the provider's `error` field, never the
            # response body/URL (which can echo submitted secrets).
            try:
                error_field = resp.json().get("error", "http_error")
            except Exception:
                error_field = "http_error"
            raise OAuthError(f"token endpoint error: {error_field}")
        return resp.json()


def _expires_at(payload: dict) -> str:
    seconds = int(payload.get("expires_in", 3600))
    now = datetime.datetime.now(datetime.timezone.utc)
    return (now + datetime.timedelta(seconds=seconds)).isoformat(timespec="seconds")


def _scopes(payload: dict) -> list[str]:
    scope = payload.get("scope", "")
    return scope.split() if scope else []


def _require_no_error(payload: dict) -> None:
    if "error" in payload:
        raise OAuthError(f"token endpoint error: {payload.get('error')}")


async def exchange_code(
    *,
    token_url: str,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
    verifier: str,
    post_form: PostForm | None = None,
) -> dict:
    post_form = post_form or _default_post_form
    payload = await post_form(
        token_url,
        {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
    )
    _require_no_error(payload)
    if "access_token" not in payload:
        raise OAuthError("token endpoint returned no access_token")
    return {
        "access_token": payload["access_token"],
        "refresh_token": payload.get("refresh_token", ""),
        "expires_at": _expires_at(payload),
        "scopes": _scopes(payload),
    }


async def refresh_access_token(
    *,
    token_url: str,
    client_id: str,
    client_secret: str,
    refresh_token: str,
    post_form: PostForm | None = None,
) -> dict:
    post_form = post_form or _default_post_form
    payload = await post_form(
        token_url,
        {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
        },
    )
    _require_no_error(payload)
    if "access_token" not in payload:
        raise OAuthError("token endpoint returned no access_token on refresh")
    return {
        "access_token": payload["access_token"],
        "expires_at": _expires_at(payload),
        "scopes": _scopes(payload),
    }


async def revoke(*, revoke_url: str, token: str, post_form: PostForm | None = None) -> None:
    post_form = post_form or _default_post_form
    await post_form(revoke_url, {"token": token})


def run_callback_server(*, port: int, expected_state: str, timeout: float = 300.0) -> str:
    captured: dict[str, str | None] = {}

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            parsed = urlparse(self.path)
            if parsed.path != "/callback":
                # Ignore stray requests (favicon, OS connectivity probes) so they
                # don't consume the wait; only the real redirect populates `captured`.
                self.send_response(404)
                self.end_headers()
                return
            query = parse_qs(parsed.query)
            captured["error"] = (query.get("error") or [None])[0]
            captured["state"] = (query.get("state") or [None])[0]
            captured["code"] = (query.get("code") or [None])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"AgentGate: you may close this tab and return to the terminal.")

        def log_message(self, *args) -> None:  # silence default logging
            pass

    # Bind IPv4 loopback explicitly (avoid dual-stack localhost -> ::1 ambiguity).
    server = HTTPServer(("127.0.0.1", port), _Handler)
    try:
        deadline = time.monotonic() + timeout
        while not captured:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            server.timeout = remaining
            server.handle_request()  # serves one request; stray hits loop again
    finally:
        server.server_close()

    if not captured:
        raise OAuthError("timed out waiting for the OAuth redirect")
    if captured.get("error"):
        raise OAuthError(f"authorization failed: {captured['error']}")
    if captured.get("state") != expected_state:
        raise OAuthError("state mismatch on OAuth callback (possible CSRF)")
    if not captured.get("code"):
        raise OAuthError("OAuth callback returned no authorization code")
    return captured["code"]
