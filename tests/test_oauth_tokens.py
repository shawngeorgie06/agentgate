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
    # expires_at is a future ISO timestamp
    assert datetime.datetime.fromisoformat(result["expires_at"]) > datetime.datetime.now()
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
