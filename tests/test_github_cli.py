import io
import json

import pytest

from broker.http_auth import create_token_file
from cli import agent


class ToolClient:
    def __init__(self, result=None, failure=None):
        self.result = result or {"ok": True, "data": []}
        self.failure = failure
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def call_tool(self, tool, values):
        self.calls.append((tool, values))
        if self.failure:
            raise self.failure
        return type("Result", (), {"data": self.result})()


@pytest.mark.asyncio
async def test_github_read_commands_map_to_bounded_mcp_calls(tmp_path, monkeypatch):
    token = tmp_path / "token"
    create_token_file(str(token))
    client = ToolClient()
    monkeypatch.setattr(agent, "Client", lambda *args, **kwargs: client)
    prefix = ["--token-file", str(token), "--agent", "agent-a"]

    async def invoke(args):
        parsed = agent.build_parser().parse_args(prefix + args)
        return await agent.execute(parsed)

    await invoke(["github", "repos", "--per-page", "25", "--page", "2"])
    await invoke(["github", "repo", "octocat", "demo"])
    await invoke(["github", "read-file", "octocat", "demo", "README.md", "--ref", "main"])
    await invoke(["github", "issues", "octocat", "demo", "--state", "all", "--limit", "10", "--page", "3"])

    assert [name for name, _ in client.calls] == ["github.repos", "github.repo", "github.read_file", "github.issues"]
    assert client.calls[0][1] == {"agent": "agent-a", "per_page": 25, "page": 2}
    assert client.calls[1][1] == {"agent": "agent-a", "owner": "octocat", "repo": "demo"}
    assert client.calls[2][1] == {"agent": "agent-a", "owner": "octocat", "repo": "demo", "path": "README.md", "ref": "main"}
    assert client.calls[3][1] == {"agent": "agent-a", "owner": "octocat", "repo": "demo", "state": "all", "limit": 10, "page": 3}


@pytest.mark.asyncio
async def test_github_create_issue_reads_body_before_single_tool_call(tmp_path, monkeypatch):
    token = tmp_path / "token"
    create_token_file(str(token))
    body_file = tmp_path / "issue.md"
    body_file.write_text("Steps\n1. Reproduce\n", encoding="utf-8")
    client = ToolClient({"ok": False, "reason": "Issue creation denied or approval timed out."})
    monkeypatch.setattr(agent, "Client", lambda *args, **kwargs: client)
    parsed = agent.build_parser().parse_args([
        "--token-file", str(token), "--agent", "agent-a", "github", "create-issue",
        "octocat", "demo", "Bug title", "--body-file", str(body_file), "--request-id", "request-1234567890",
    ])
    result = await agent.execute(parsed)
    assert result["ok"] is False
    assert client.calls == [("github.create_issue", {
        "agent": "agent-a", "owner": "octocat", "repo": "demo", "title": "Bug title",
        "body": "Steps\n1. Reproduce\n", "request_id": "request-1234567890",
    })]


@pytest.mark.parametrize("command", [
    ["github", "create-issue", "octocat", "demo", "title"],
    ["github", "repos", "--per-page", "101"],
    ["github", "issues", "octocat", "demo", "--limit", "0"],
    ["github", "issues", "octocat", "demo", "--page", "0"],
])
def test_github_cli_invalid_requests_are_rejected(command):
    with pytest.raises(SystemExit) as error:
        agent.run(command)
    assert error.value.code == 2


@pytest.mark.parametrize("during_dispatch", [False, True])
def test_issue_connection_failure_warns_to_reuse_same_request_id(tmp_path, monkeypatch, capsys, during_dispatch):
    import httpx2
    token = tmp_path / "token"
    create_token_file(str(token))
    body = tmp_path / "body.txt"
    body.write_text("Body\n", encoding="utf-8")

    class BrokenClient:
        async def __aenter__(self):
            if not during_dispatch:
                try:
                    raise httpx2.ConnectError("Bearer secret-token")
                except Exception as exc:
                    raise RuntimeError("Client startup failed") from exc
            return self
        async def __aexit__(self, *args):
            return None
        async def call_tool(self, *args):
            raise httpx2.ConnectError("Bearer secret-token")

    monkeypatch.setattr(agent, "Client", lambda *args, **kwargs: BrokenClient())
    args = ["--token-file", str(token), "github", "create-issue", "octocat", "demo", "Bug",
            "--body-file", str(body), "--request-id", "request-1234567890"]
    assert agent.run(args) == 1
    result = json.loads(capsys.readouterr().out)
    assert ("notice" in result) is during_dispatch
    assert "secret-token" not in json.dumps(result)
    if during_dispatch:
        assert "same request ID" in result["notice"]

