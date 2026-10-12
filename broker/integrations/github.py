"""Bounded GitHub REST access with a single locally stored fine-grained token."""
from __future__ import annotations

import base64
import binascii
import json
import threading
from typing import Callable
from urllib.parse import quote

import requests

from broker.credential_store import CredentialDecryptionError, CredentialStore

INTERNAL_PREFIX = "__agentgate:"
TOKEN_NAME = INTERNAL_PREFIX + "github-token"
ACCOUNT_NAME = INTERNAL_PREFIX + "github-account"
API_BASE = "https://api.github.com"
API_VERSION = "2022-11-28"
_MAX_FILE_SIZE = 1024 * 1024


class GitHubError(Exception):
    """Safe, provider-independent error suitable for returning to an agent."""

    @property
    def safe_message(self):
        return str(self)


def _segment(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value in {".", ".."}:
        raise GitHubError(f"{label} must be a non-empty path segment.")
    if any(ord(char) < 32 or char in "/\\?#%" for char in value):
        raise GitHubError(f"{label} contains unsupported characters.")
    return quote(value, safe="-._~")


def _page(value: object, label: str, *, maximum: int = 10000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise GitHubError(f"{label} must be between 1 and {maximum}.")
    return value


def _account(data: object) -> dict:
    if not isinstance(data, dict) or not isinstance(data.get("login"), str) or not data["login"]:
        raise GitHubError("GitHub returned an unexpected account response.")
    account = {"login": data["login"]}
    if isinstance(data.get("id"), int) and not isinstance(data.get("id"), bool):
        account["id"] = data["id"]
    return account


class GitHub:
    """Serialize API use; fetch the current encrypted token for every call."""

    def __init__(self, store: CredentialStore, request_session=None):
        self.store = store
        self._session = request_session or requests.Session()
        self._lock = threading.RLock()
        self._suspended = False

    def _send(self, method: str, path: str, *, token: str, params=None, json_body=None):
        # URL construction stays inside this fixed allowlist; no response-provided
        # pagination or download URLs are ever followed.
        url = API_BASE + path
        try:
            response = self._session.request(
                method, url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": API_VERSION,
                },
                params=params, json=json_body, timeout=30, allow_redirects=False,
            )
        except (requests.RequestException, OSError, TimeoutError):
            raise GitHubError("GitHub could not be reached. Check your connection.") from None
        status = response.status_code
        if status < 200 or status >= 300:
            if status == 401:
                raise GitHubError("GitHub authorization needs renewal. Reconnect GitHub.")
            raise GitHubError(f"GitHub API request failed (HTTP {status}).")
        try:
            data = response.json()
        except (ValueError, TypeError):
            raise GitHubError("GitHub returned an unexpected response.") from None
        return data

    def _fetch_account(self, token: str) -> dict:
        return _account(self._send("GET", "/user", token=token))

    def connect(self, token: str) -> dict:
        """Validate staged PAT before atomically replacing local token metadata."""
        if not isinstance(token, str) or not token or len(token) > 4096 or any(c.isspace() for c in token):
            raise GitHubError("Enter a valid GitHub fine-grained personal access token.")
        with self._lock:
            # Explicit candidate is used only for this fixed `/user` request. The old
            # encrypted values remain intact until the validation succeeds.
            account = self._fetch_account(token)
            self.store.update({TOKEN_NAME: token,
                               ACCOUNT_NAME: json.dumps(account, separators=(",", ":"))})
            self._suspended = False
            return account

    def info(self) -> dict:
        """Return cached safe account metadata and local connection health."""
        with self._lock:
            if self._suspended:
                return {"service": "github", "status": "disconnected", "account": None}
            try:
                token = self.store.retrieve(TOKEN_NAME)
            except KeyError:
                return {"service": "github", "status": "disconnected", "account": None}
            except CredentialDecryptionError:
                return {"service": "github", "status": "unavailable", "account": None,
                        "error": "GitHub account status could not be checked."}
            if not token:
                return {"service": "github", "status": "needs_reconnect", "account": None}
            try:
                account = json.loads(self.store.retrieve(ACCOUNT_NAME))
                account = _account(account)
            except (KeyError, ValueError, TypeError, GitHubError):
                return {"service": "github", "status": "needs_reconnect", "account": None}
            return {"service": "github", "status": "connected", "account": account}

    def disconnect(self) -> None:
        """Remove the local PAT; GitHub token revocation is not attempted."""
        with self._lock:
            self._suspended = True
            self.store.update({}, delete=(TOKEN_NAME, ACCOUNT_NAME))

    def call(self, operation: str, *, before_dispatch: Callable[[], None] | None = None, **arguments) -> dict | list:
        with self._lock:
            if self._suspended:
                raise GitHubError("GitHub is not connected. Connect GitHub in the operator settings.")
            try:
                token = self.store.retrieve(TOKEN_NAME)
            except KeyError:
                raise GitHubError("GitHub is not connected. Connect GitHub in the operator settings.") from None
            if not token:
                raise GitHubError("GitHub is not connected. Connect GitHub in the operator settings.")

            if operation == "account":
                if before_dispatch is not None:
                    before_dispatch()
                return self._fetch_account(token)
            if operation == "repos":
                per_page = arguments.get("per_page", 30)
                if isinstance(per_page, bool) or not isinstance(per_page, int) or not 1 <= per_page <= 100:
                    raise GitHubError("per_page must be between 1 and 100.")
                page = _page(arguments.get("page", 1), "page")
                if before_dispatch is not None:
                    before_dispatch()
                data = self._send("GET", "/user/repos", token=token,
                                  params={"per_page": per_page, "page": page, "sort": "full_name"})
                if not isinstance(data, list):
                    raise GitHubError("GitHub returned an unexpected repository response.")
                return [self._repo(item) for item in data]
            if operation == "repo":
                owner, repo = self._owner_repo(arguments)
                if before_dispatch is not None:
                    before_dispatch()
                data = self._send("GET", f"/repos/{owner}/{repo}", token=token)
                return self._repo(data)
            if operation == "read_file":
                owner, repo = self._owner_repo(arguments)
                path = arguments.get("path")
                if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path:
                    raise GitHubError("path must be a relative repository file path.")
                parts = path.split("/")
                if any(part in {"", ".", ".."} for part in parts):
                    raise GitHubError("path must not contain traversal segments.")
                encoded = "/".join(quote(part, safe="-._~") for part in parts)
                ref = arguments.get("ref")
                params = None
                if ref is not None:
                    if not isinstance(ref, str) or not ref or len(ref) > 255 or any(ord(c) < 32 for c in ref):
                        raise GitHubError("ref must be a non-empty Git reference.")
                    params = {"ref": ref}
                if before_dispatch is not None:
                    before_dispatch()
                data = self._send("GET", f"/repos/{owner}/{repo}/contents/{encoded}", token=token, params=params)
                if not isinstance(data, dict) or data.get("type") != "file":
                    raise GitHubError("The requested repository path is not a file.")
                size = data.get("size")
                if isinstance(size, bool) or not isinstance(size, int) or size < 0 or size > _MAX_FILE_SIZE:
                    raise GitHubError("The requested file exceeds the 1 MiB text limit.")
                if data.get("encoding") != "base64" or not isinstance(data.get("content"), str):
                    raise GitHubError("GitHub returned an unsupported file encoding.")
                try:
                    raw = base64.b64decode("".join(data["content"].split()), validate=True)
                    if len(raw) > _MAX_FILE_SIZE:
                        raise ValueError
                    content = raw.decode("utf-8")
                except (ValueError, UnicodeError, binascii.Error):
                    raise GitHubError("The requested file is not supported UTF-8 text.") from None
                if len(raw) != size:
                    raise GitHubError("GitHub returned an incomplete file.")
                return {"path": path, "ref": ref, "content": content, "size": size}
            if operation == "issues":
                owner, repo = self._owner_repo(arguments)
                state = arguments.get("state", "open")
                if state not in {"open", "closed", "all"}:
                    raise GitHubError("state must be open, closed, or all.")
                per_page = arguments.get("limit", 30)
                if isinstance(per_page, bool) or not isinstance(per_page, int) or not 1 <= per_page <= 100:
                    raise GitHubError("limit must be between 1 and 100.")
                page = _page(arguments.get("page", 1), "page")
                if before_dispatch is not None:
                    before_dispatch()
                data = self._send("GET", f"/repos/{owner}/{repo}/issues", token=token,
                                  params={"state": state, "per_page": per_page, "page": page})
                if not isinstance(data, list):
                    raise GitHubError("GitHub returned an unexpected issue response.")
                return [self._issue(item) for item in data if isinstance(item, dict) and "pull_request" not in item]
            if operation == "create_issue":
                owner, repo = self._owner_repo(arguments)
                title, body = arguments.get("title"), arguments.get("body", "")
                if not isinstance(title, str) or not title.strip() or len(title) > 256 or "\n" in title or "\r" in title:
                    raise GitHubError("title must be a single non-empty line of at most 256 characters.")
                if not isinstance(body, str) or len(body) > 65536:
                    raise GitHubError("body must be text of at most 65536 characters.")
                if before_dispatch is not None:
                    before_dispatch()
                data = self._send("POST", f"/repos/{owner}/{repo}/issues", token=token,
                                  json_body={"title": title, "body": body})
                if not isinstance(data, dict) or not isinstance(data.get("number"), int):
                    raise GitHubError("GitHub returned an unexpected issue response.")
                return {"number": data["number"], "html_url": data.get("html_url")}
            raise GitHubError("Unsupported GitHub operation.")

    @staticmethod
    def _owner_repo(arguments) -> tuple[str, str]:
        return (_segment(arguments.get("owner"), "owner"), _segment(arguments.get("repo"), "repo"))

    @staticmethod
    def _repo(item: object) -> dict:
        if not isinstance(item, dict):
            raise GitHubError("GitHub returned an unexpected repository response.")
        keys = ("id", "name", "full_name", "private", "description", "html_url", "default_branch", "language", "updated_at")
        return {key: item[key] for key in keys if key in item}

    @staticmethod
    def _issue(item: dict) -> dict:
        keys = ("number", "title", "state", "html_url", "user", "labels", "created_at", "updated_at", "body")
        result = {key: item[key] for key in keys if key in item}
        if isinstance(result.get("user"), dict):
            result["user"] = {key: result["user"][key] for key in ("login", "id") if key in result["user"]}
        if isinstance(result.get("labels"), list):
            result["labels"] = [label.get("name") for label in result["labels"] if isinstance(label, dict) and isinstance(label.get("name"), str)]
        return result
