from __future__ import annotations

import threading
import time
import urllib.request

from broker import oauth


def _hit(port: int, query: str):
    # Retry briefly until the server thread has bound the port. Hit 127.0.0.1 to
    # match the server's explicit IPv4 bind. Fail loudly if never reachable.
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/callback?{query}", timeout=2)
            return
        except Exception:
            time.sleep(0.05)
    raise AssertionError(f"callback server on port {port} was never reachable")


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


def _hit_path(port: int, path: str):
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=2)
            return
        except urllib.error.HTTPError:
            return  # a 404 (stray request) still counts as "reached"
        except Exception:
            time.sleep(0.05)
    raise AssertionError(f"server on port {port} was never reachable")


def test_callback_error_param_raises():
    port = 8793
    error = {}

    def run():
        try:
            oauth.run_callback_server(port=port, expected_state="st8", timeout=10)
        except oauth.OAuthError as exc:
            error["msg"] = str(exc)

    t = threading.Thread(target=run)
    t.start()
    _hit(port, "error=access_denied&state=st8")
    t.join(timeout=10)
    assert "access_denied" in error["msg"]


def test_callback_ignores_stray_request_then_serves_redirect():
    # A favicon/probe hits first; the server must skip it and still serve /callback.
    port = 8794
    result = {}

    def run():
        result["code"] = oauth.run_callback_server(
            port=port, expected_state="st8", timeout=10
        )

    t = threading.Thread(target=run)
    t.start()
    _hit_path(port, "/favicon.ico")          # stray request -> 404, must not consume the wait
    _hit(port, "code=realcode&state=st8")    # the real redirect
    t.join(timeout=10)
    assert result["code"] == "realcode"


def test_callback_times_out():
    # No request arrives; a short timeout must raise rather than hang.
    import pytest

    with pytest.raises(oauth.OAuthError) as exc:
        oauth.run_callback_server(port=8795, expected_state="st8", timeout=0.3)
    assert "timed out" in str(exc.value).lower()
