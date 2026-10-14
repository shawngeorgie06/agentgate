"""GitHub provider and tool boundary tests. All HTTP is mocked."""
from __future__ import annotations

import asyncio
import base64
import dataclasses
import json
import threading

import pytest
from fastmcp import Client, FastMCP

from broker.github_tools import GitHubTools, register_github_tools
from broker.integrations.github import (
    ACCOUNT_NAME,
    TOKEN_NAME,
    GitHub,
    GitHubError,
)
from broker.main import build_broker
from broker.policy_engine import PolicyEngine
from tests.test_main import _cfg


class MemoryStore:
    def __init__(self, token="fine-grained-token"):
        self.values = {TOKEN_NAME: token} if token else {}

    def store(self, key, value):
        self.values[key] = value

    def update(self, values, *, delete=()):
        for key in delete: self.values.pop(key, None)
        self.values.update(values)

    def retrieve(self, key):
        if key not in self.values:
            raise KeyError(key)
        return self.values[key]

    def delete(self, key):
        del self.values[key]

    def list_names(self):
        return sorted(self.values)


class Response:
    def __init__(self, status=200, data=None, *, text=None, headers=None):
        self.status_code = status
        self._data = data
        self.text = text or ""
        self.headers = headers or {}

    def json(self):
        if isinstance(self._data, Exception):
            raise self._data
        return self._data


class Session:
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        next_response = self.responses.pop(0)
        if isinstance(next_response, Exception):
            raise next_response
        return next_response


def provider(responses=None, token="fine-grained-token"):
    store = MemoryStore(token)
    session = Session(responses)
    return GitHub(store, request_session=session), store, session


def test_account_and_repo_reads_use_fixed_api_and_safe_headers():
    github, _, session = provider([
        Response(data={"login": "octocat", "id": 1, "email": "private@example.test"}),
        Response(data=[{"id": 42, "name": "demo", "full_name": "octocat/demo", "private": False}]),
    ])
    assert github.call("account") == {"login": "octocat", "id": 1}
    assert github.call("repos", per_page=50, page=2) == [
        {"id": 42, "name": "demo", "full_name": "octocat/demo", "private": False}
    ]
    method, url, options = session.calls[0]
    assert method == "GET" and url == "https://api.github.com/user"
    assert options["headers"] == {
        "Authorization": "Bearer fine-grained-token",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    assert options["timeout"] == 30
    assert options["allow_redirects"] is False


def test_read_file_decodes_small_text_without_following_download_url():
    payload = base64.b64encode("hello, GitHub\n".encode()).decode()
    github, _, session = provider([Response(data={
        "type": "file", "encoding": "base64", "size": 14,
        "content": payload, "download_url": "https://attacker.invalid/secret",
    })])
    result = github.call("read_file", owner="octocat", repo="demo", path="docs/hello world.md", ref="main")
    assert result == {"path": "docs/hello world.md", "ref": "main", "content": "hello, GitHub\n", "size": 14}
    assert session.calls[0][1] == "https://api.github.com/repos/octocat/demo/contents/docs/hello%20world.md"
    assert session.calls[0][2]["params"] == {"ref": "main"}
    assert len(session.calls) == 1


@pytest.mark.parametrize("owner,repo,path", [
    ("../evil", "repo", "README.md"), ("owner", "repo?x=1", "README.md"),
    ("owner", "repo", "../secret"), ("owner", "repo", "/etc/passwd"),
    ("owner", "repo", "a/../../secret"),
])
def test_rejects_path_traversal_or_url_control(owner, repo, path):
    github, _, session = provider([])
    with pytest.raises(GitHubError):
        github.call("read_file", owner=owner, repo=repo, path=path)
    assert not session.calls


@pytest.mark.parametrize("per_page,page", [(0, 1), (101, 1), (20, 0), (20, -1), (20, 10001)])
def test_rejects_unbounded_pagination(per_page, page):
    github, _, session = provider([])
    with pytest.raises(GitHubError):
        github.call("repos", per_page=per_page, page=page)
    assert not session.calls


def test_http_errors_never_echo_provider_body_headers_or_token():
    secret = "ghp_super_secret"
    github, _, session = provider([
        Response(status=401, data={"message": secret}, text=secret, headers={"Authorization": secret})
    ], token=secret)
    with pytest.raises(GitHubError) as caught:
        github.call("account")
    assert "authorization needs renewal" in str(caught.value)
    assert secret not in str(caught.value)


def test_call_reads_encrypted_store_fresh_and_disconnect_suspends():
    github, store, session = provider([Response(data={"login": "first", "id": 1}), Response(data={"login": "second", "id": 2})])
    github.call("account")
    store.store(TOKEN_NAME, "rotated")
    github.call("account")
    assert session.calls[0][2]["headers"]["Authorization"] == "Bearer fine-grained-token"
    assert session.calls[1][2]["headers"]["Authorization"] == "Bearer rotated"
    github._suspended = True
    with pytest.raises(GitHubError):
        github.call("account")
    assert len(session.calls) == 2


def test_revoked_read_guard_after_waiting_for_transport_lock_prevents_get():
    github, _, session = provider([])
    entered = threading.Event()
    active = True
    result = []

    def request():
        entered.set()
        try:
            result.append(github.call("repos", before_dispatch=lambda: (_ for _ in ()).throw(GitHubError("revoked")) if not active else None))
        except GitHubError as exc:
            result.append(str(exc))

    github._lock.acquire()
    worker = threading.Thread(target=request)
    worker.start()
    assert entered.wait(1)
    active = False
    github._lock.release()
    worker.join(2)
    assert not worker.is_alive()
    assert result == ["revoked"]
    assert session.calls == []


def test_connect_validates_candidate_before_replacing_existing_credentials():
    github, store, session = provider([Response(status=401, data={"message": "bad"})])
    with pytest.raises(GitHubError):
        github.connect("invalid-candidate")
    assert store.retrieve(TOKEN_NAME) == "fine-grained-token"
    assert ACCOUNT_NAME not in store.list_names()
    assert session.calls[0][2]["headers"]["Authorization"] == "Bearer invalid-candidate"


def test_connect_persists_only_safe_account_metadata():
    github, store, session = provider([Response(data={"login": "octocat", "id": 1, "email": "hidden@example.test"})], token=None)
    assert github.connect("fine-grained-token") == {"login": "octocat", "id": 1}
    assert store.retrieve(TOKEN_NAME) == "fine-grained-token"
    assert json.loads(store.retrieve(ACCOUNT_NAME)) == {"login": "octocat", "id": 1}
    assert "hidden@example.test" not in json.dumps(store.values)


def test_info_reports_cached_safe_account_without_network_calls():
    github, store, session = provider([])
    store.store(ACCOUNT_NAME, json.dumps({"login": "octocat", "id": 1}))
    assert github.info() == {"service": "github", "status": "connected", "account": {"login": "octocat", "id": 1}}
    assert session.calls == []


def test_post_does_not_follow_redirect_or_retry_after_uncertain_failure():
    github, _, session = provider([Response(status=502, text="sensitive response")])
    with pytest.raises(GitHubError):
        github.call("create_issue", owner="octocat", repo="demo", title="Bug", body="Details")
    assert len(session.calls) == 1
    assert session.calls[0][0] == "POST"
    assert session.calls[0][1] == "https://api.github.com/repos/octocat/demo/issues"
    assert session.calls[0][2]["allow_redirects"] is False


def broker_tools(tmp_path, responses):
    broker = build_broker(_cfg(tmp_path), "pw")
    broker.engine = PolicyEngine([{
        "name": "github-read", "agent": "agent-a", "credential": "*",
        "auto_approve": True, "escalate": False,
    }])
    github = GitHub(broker.store, request_session=Session(responses))
    broker.store.store(TOKEN_NAME, "fine-grained-token")
    return broker, github, GitHubTools(broker, github)


async def pending(broker):
    async with asyncio.timeout(3):
        while broker.approvals.get_pending() is None:
            await asyncio.sleep(0.01)
    return broker.approvals.get_pending()


@pytest.mark.asyncio
@pytest.mark.parametrize("approve", [True, False])
async def test_issue_create_always_requires_approval_and_freezes_exact_payload(tmp_path, approve):
    broker, github, tools = broker_tools(tmp_path, [
        Response(data={"number": 9, "html_url": "https://github.com/octocat/demo/issues/9"}),
    ])
    issue = {"owner": "octocat", "repo": "demo", "title": "Exact title", "body": "Exact body", "request_id": "request-1234567890"}
    task = asyncio.create_task(tools.create_issue("agent-a", **issue))
    request = await pending(broker)
    frozen = json.loads(request.details)
    assert request.credential == "github:write"
    assert frozen == {"owner": "octocat", "repo": "demo", "title": "Exact title", "body": "Exact body"}
    assert github._session.calls == []  # issue POST waits for approval
    issue.update(title="Changed while approval is pending", body="Changed body")
    broker.approvals.resolve(request, approve)
    result = await task
    assert result["ok"] is approve
    assert len(github._session.calls) == int(approve)
    if approve:
        assert github._session.calls[0][2]["json"] == {"title": "Exact title", "body": "Exact body"}
    assert "Exact body" not in open(broker.config.logs_path).read()


@pytest.mark.asyncio
async def test_expired_issue_approval_never_dispatches(tmp_path):
    broker, github, tools = broker_tools(tmp_path, [Response(data={"number": 9})])
    broker.config = dataclasses.replace(broker.config, escalation_timeout_seconds=0.01)
    result = await tools.create_issue(
        "agent-a", owner="octocat", repo="demo", title="Expired", body="Body",
        request_id="request-1234567890",
    )
    assert result["ok"] is False
    assert "timed out" in result["reason"]
    assert github._session.calls == []


@pytest.mark.asyncio
async def test_issue_attempt_id_is_persisted_before_dispatch_and_duplicate_is_blocked(tmp_path):
    broker, github, tools = broker_tools(tmp_path, [
        TimeoutError("response loss after server may have created issue"),
    ])
    task = asyncio.create_task(tools.create_issue(
        "agent-a", owner="octocat", repo="demo", title="Possible duplicate", body="Body",
        request_id="request-1234567890",
    ))
    request = await pending(broker)
    broker.approvals.resolve(request, True)
    result = await task
    assert result["ok"] is False
    assert "uncertain" in result["reason"].lower()
    restarted_tools = GitHubTools(broker, github)
    again = await restarted_tools.create_issue(
        "agent-a", owner="octocat", repo="demo", title="Possible duplicate", body="Body",
        request_id="request-1234567890",
    )
    assert again["ok"] is False
    assert len(github._session.calls) == 1


@pytest.mark.asyncio
async def test_registration_requires_trusted_identity_resolver(tmp_path):
    broker, github, _ = broker_tools(tmp_path, [])
    mcp = FastMCP("GitHub identity test")
    with pytest.raises(ValueError):
        register_github_tools(mcp, broker, github)


@pytest.mark.asyncio
async def test_registered_read_tool_uses_server_resolved_identity(tmp_path):
    broker, github, _ = broker_tools(tmp_path, [Response(data=[{"id": 5, "name": "demo", "full_name": "octocat/demo", "private": False}])])
    mcp = FastMCP("GitHub tool test")
    register_github_tools(mcp, broker, github, identity_resolver=lambda _supplied: ("agent-a", lambda: True))
    async with Client(mcp) as client:
        result = (await client.call_tool("github.repos", {"agent": "attacker", "per_page": 10, "page": 1})).data
    assert result["ok"] is True
    assert github._session.calls[0][2]["headers"]["Authorization"] == "Bearer fine-grained-token"
