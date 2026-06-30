from __future__ import annotations

from broker import oauth
from broker.config import Config
from broker.connection_store import Connection, ConnectionStore
from cli import commands


def _cfg(tmp_path):
    env = {
        "POLICIES_PATH": str(tmp_path / "policies.yaml"),
        "STATE_PATH": str(tmp_path / "mode.json"),
        "LOGS_PATH": str(tmp_path / "audit.log"),
        "CREDENTIALS_PATH": str(tmp_path / "creds.json"),
        "CONNECTIONS_PATH": str(tmp_path / "connections.json"),
    }
    return Config.from_env(env)


def test_connections_lists_without_secrets(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    ConnectionStore(cfg.connections_path, "pw").store("work", Connection(
        provider="google", client_id="cid", client_secret="csec", refresh_token="rt",
        scopes=["openid"], created_at="2026-06-27T10:00:00"))
    rc = commands.run(["connections"], config=cfg, master_password="pw")
    out = capsys.readouterr().out
    assert rc == 0
    assert "work" in out and "google" in out
    assert "csec" not in out and "rt" not in out


def test_disconnect_revokes_and_deletes(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    store = ConnectionStore(cfg.connections_path, "pw")
    store.store("work", Connection(
        provider="google", client_id="cid", client_secret="csec", refresh_token="rt",
        scopes=["openid"], created_at="2026-06-27T10:00:00"))
    revoked = {}

    async def fake_revoke(**kwargs):
        revoked["token"] = kwargs["token"]
    monkeypatch.setattr(oauth, "revoke", fake_revoke)

    rc = commands.run(["disconnect", "work"], config=cfg, master_password="pw")
    assert rc == 0
    assert revoked["token"] == "rt"
    assert ConnectionStore(cfg.connections_path, "pw").list_names() == []


def test_disconnect_deletes_even_if_revoke_fails(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    ConnectionStore(cfg.connections_path, "pw").store("work", Connection(
        provider="google", client_id="cid", client_secret="csec", refresh_token="rt",
        scopes=["openid"], created_at="2026-06-27T10:00:00"))

    async def failing_revoke(**kwargs):
        raise oauth.OAuthError("token endpoint error: invalid_token")
    monkeypatch.setattr(oauth, "revoke", failing_revoke)

    rc = commands.run(["disconnect", "work"], config=cfg, master_password="pw")
    # Lenient: a failed remote revoke must not block local removal.
    assert rc == 0
    assert ConnectionStore(cfg.connections_path, "pw").list_names() == []


def test_connect_stores_connection(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    monkeypatch.setenv("AGENTGATE_OAUTH_CLIENT_ID", "cid")
    monkeypatch.setenv("AGENTGATE_OAUTH_CLIENT_SECRET", "csec")
    monkeypatch.setattr(commands.webbrowser, "open", lambda url: True)

    # Assert the CSRF state token is actually handed to the callback server.
    def fake_callback(**kw):
        assert "expected_state" in kw and kw["expected_state"]
        return "authcode"
    monkeypatch.setattr(oauth, "run_callback_server", fake_callback)

    async def fake_exchange(**kwargs):
        return {"access_token": "AT", "refresh_token": "RT-new",
                "expires_at": "2099-01-01T00:00:00", "scopes": ["openid", "email"]}
    monkeypatch.setattr(oauth, "exchange_code", fake_exchange)

    rc = commands.run(["connect", "google", "work"], config=cfg, master_password="pw")
    assert rc == 0
    conn = ConnectionStore(cfg.connections_path, "pw").get("work")
    assert conn.refresh_token == "RT-new"
    assert conn.provider == "google"
    assert conn.scopes == ["openid", "email"]
