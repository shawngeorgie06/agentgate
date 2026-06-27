from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import pytest

from broker import oauth


def test_get_preset_known_and_unknown():
    assert oauth.get_preset("google").token_url.startswith("https://")
    assert oauth.get_preset("github").auth_url.startswith("https://")
    with pytest.raises(oauth.OAuthError):
        oauth.get_preset("nope")


def test_generate_pkce_s256():
    verifier, challenge = oauth.generate_pkce()
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    assert challenge == expected
    assert 43 <= len(verifier) <= 128


def test_build_auth_url_contains_params():
    preset = oauth.get_preset("google")
    url = oauth.build_auth_url(
        preset=preset,
        client_id="cid",
        redirect_uri="http://localhost:8765/callback",
        scopes=["openid", "email"],
        state="st8",
        challenge="chal",
    )
    q = parse_qs(urlparse(url).query)
    assert q["client_id"] == ["cid"]
    assert q["redirect_uri"] == ["http://localhost:8765/callback"]
    assert q["state"] == ["st8"]
    assert q["code_challenge"] == ["chal"]
    assert q["code_challenge_method"] == ["S256"]
    assert q["response_type"] == ["code"]
    assert q["scope"] == ["openid email"]


def test_google_includes_offline_github_does_not():
    google_url = oauth.build_auth_url(
        preset=oauth.get_preset("google"),
        client_id="cid",
        redirect_uri="http://localhost:8765/callback",
        scopes=["openid", "email"],
        state="st8",
        challenge="chal",
    )
    gq = parse_qs(urlparse(google_url).query)
    assert gq["access_type"] == ["offline"]
    assert gq["prompt"] == ["consent"]

    github_url = oauth.build_auth_url(
        preset=oauth.get_preset("github"),
        client_id="cid",
        redirect_uri="http://localhost:8765/callback",
        scopes=["read:user"],
        state="st8",
        challenge="chal",
    )
    hq = parse_qs(urlparse(github_url).query)
    assert "access_type" not in hq
    assert "prompt" not in hq
