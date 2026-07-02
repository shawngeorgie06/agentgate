from __future__ import annotations

import datetime

import pytest

from broker import oauth


def _fake_post(response: dict):
    calls = []

    async def post_form(url: str, data: dict) -> dict:
        calls.append((url, data))
        return response

    post_form.calls = calls
    return post_form


async def test_exchange_code_parses_tokens():
    post = _fake_post({
        "access_token": "at-1", "refresh_token": "rt-1",
        "expires_in": 3600, "scope": "openid email",
    })
    result = await oauth.exchange_code(
        token_url="https://t", client_id="c", client_secret="s",
        code="authcode", redirect_uri="http://localhost:8765/callback",
        verifier="ver", post_form=post,
    )
    assert result["access_token"] == "at-1"
    assert result["refresh_token"] == "rt-1"
    assert result["scopes"] == ["openid", "email"]
    # expires_at is a future, timezone-aware (UTC) ISO timestamp
    expires = datetime.datetime.fromisoformat(result["expires_at"])
    assert expires.tzinfo is not None
    assert expires > datetime.datetime.now(datetime.timezone.utc)
    # grant_type and PKCE verifier were sent
    _, sent = post.calls[0]
    assert sent["grant_type"] == "authorization_code"
    assert sent["code_verifier"] == "ver"


async def test_exchange_code_error_response_raises():
    post = _fake_post({"error": "invalid_grant"})
    with pytest.raises(oauth.OAuthError):
        await oauth.exchange_code(
            token_url="https://t", client_id="c", client_secret="s",
            code="bad", redirect_uri="http://localhost:8765/callback",
            verifier="ver", post_form=post,
        )


async def test_refresh_access_token_parses():
    post = _fake_post({"access_token": "at-2", "expires_in": 1800, "scope": "read:user"})
    result = await oauth.refresh_access_token(
        token_url="https://t", client_id="c", client_secret="s",
        refresh_token="rt-1", post_form=post,
    )
    assert result["access_token"] == "at-2"
    assert result["scopes"] == ["read:user"]
    _, sent = post.calls[0]
    assert sent["grant_type"] == "refresh_token"
    assert sent["refresh_token"] == "rt-1"


async def test_revoke_calls_endpoint():
    post = _fake_post({})
    await oauth.revoke(revoke_url="https://r", token="rt-1", post_form=post)
    assert post.calls[0][0] == "https://r"
    assert post.calls[0][1]["token"] == "rt-1"


def _mock_httpx(handler):
    """Patch httpx.AsyncClient to route through a MockTransport. Returns a restore fn."""
    import httpx

    transport = httpx.MockTransport(handler)
    orig = httpx.AsyncClient

    def patched(*a, **k):
        k["transport"] = transport
        return orig(*a, **k)

    httpx.AsyncClient = patched
    return lambda: setattr(httpx, "AsyncClient", orig)


async def test_default_post_form_sanitizes_http_error():
    import httpx

    def handler(request):
        return httpx.Response(
            400, json={"error": "invalid_grant", "error_description": "SENSITIVE-rt-xyz"}
        )

    restore = _mock_httpx(handler)
    try:
        with pytest.raises(oauth.OAuthError) as exc:
            await oauth._default_post_form("https://token", {"grant_type": "x"})
    finally:
        restore()
    # Only the `error` field surfaces; the sensitive description/body never does.
    assert "invalid_grant" in str(exc.value)
    assert "SENSITIVE" not in str(exc.value)


async def test_default_post_form_success():
    import httpx

    def handler(request):
        return httpx.Response(200, json={"access_token": "AT", "expires_in": 3600})

    restore = _mock_httpx(handler)
    try:
        result = await oauth._default_post_form("https://token", {"grant_type": "x"})
    finally:
        restore()
    assert result["access_token"] == "AT"
