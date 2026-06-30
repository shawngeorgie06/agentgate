from __future__ import annotations

import threading
import time
import urllib.request

import pytest

from broker import oauth


def _hit(port: int, query: str):
    # Retry briefly until the server thread has bound the port.
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://localhost:{port}/callback?{query}", timeout=2)
            return
        except Exception:
            time.sleep(0.05)


def test_callback_returns_code():
    port = 8791
    result = {}

    def run():
        result["code"] = oauth.run_callback_server(
            port=port, expected_state="st8", timeout=10
        )

    t = threading.Thread(target=run)
    t.start()
    _hit(port, "code=authcode123&state=st8")
    t.join(timeout=10)
    assert result["code"] == "authcode123"


def test_callback_rejects_bad_state():
    port = 8792
    error = {}

    def run():
        try:
            oauth.run_callback_server(port=port, expected_state="GOOD", timeout=10)
        except oauth.OAuthError as exc:
            error["msg"] = str(exc)

    t = threading.Thread(target=run)
    t.start()
    _hit(port, "code=x&state=EVIL")
    t.join(timeout=10)
    assert "state" in error["msg"].lower()
