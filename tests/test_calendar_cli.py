import json

import pytest

from broker.http_auth import create_token_file
from cli import agent
from tests.test_github_cli import ToolClient


@pytest.mark.asyncio
async def test_calendar_commands_map_to_bounded_mcp_calls(tmp_path, monkeypatch):
    token = tmp_path / "token"
    create_token_file(str(token))
    description = tmp_path / "event.txt"
    description.write_text("Bring forms\n", encoding="utf-8")
    client = ToolClient()
    monkeypatch.setattr(agent, "Client", lambda *args, **kwargs: client)
    prefix = ["--token-file", str(token), "--agent", "agent-a", "calendar"]

    async def invoke(args):
        return await agent.execute(agent.build_parser().parse_args(prefix + args))

    await invoke(["calendars", "--limit", "10"])
    await invoke(["events", "2026-11-20T00:00:00-05:00", "2026-11-21T00:00:00-05:00", "--query", "standup"])
    await invoke(["freebusy", "2026-11-20T00:00:00Z", "2026-11-21T00:00:00Z", "--calendar-id", "primary", "--calendar-id", "team@example.test"])
    await invoke(["create-event", "Dentist", "2026-11-20T09:00:00-05:00", "2026-11-20T10:00:00-05:00",
                  "--time-zone", "America/New_York", "--description-file", str(description),
                  "--request-id", "request-1234567890"])

    assert [name for name, _ in client.calls] == [
        "calendar.calendars", "calendar.events", "calendar.freebusy", "calendar.create_event"]
    assert client.calls[0][1] == {"agent": "agent-a", "limit": 10, "page_token": None}
    assert client.calls[1][1] == {"agent": "agent-a", "time_min": "2026-11-20T00:00:00-05:00",
                                  "time_max": "2026-11-21T00:00:00-05:00", "calendar_id": "primary",
                                  "query": "standup", "limit": 25, "page_token": None}
    assert client.calls[2][1]["calendar_ids"] == ["primary", "team@example.test"]
    assert client.calls[3][1] == {
        "agent": "agent-a", "summary": "Dentist", "start": "2026-11-20T09:00:00-05:00",
        "end": "2026-11-20T10:00:00-05:00", "time_zone": "America/New_York", "location": "",
        "description": "Bring forms\n", "calendar_id": "primary", "request_id": "request-1234567890",
    }


@pytest.mark.parametrize("command", [
    ["calendar", "create-event", "Title", "2026-11-20", "2026-11-21"],
    ["calendar", "calendars", "--limit", "251"],
    ["calendar", "events", "2026-11-20T00:00:00Z", "2026-11-21T00:00:00Z", "--limit", "0"],
])
def test_calendar_cli_invalid_requests_are_rejected(command):
    with pytest.raises(SystemExit) as error:
        agent.run(command)
    assert error.value.code == 2


def test_event_connection_failure_warns_to_reuse_same_request_id(tmp_path, monkeypatch, capsys):
    import httpx2
    token = tmp_path / "token"
    create_token_file(str(token))

    class BrokenClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return None
        async def call_tool(self, *args):
            raise httpx2.ConnectError("Bearer secret-token")

    monkeypatch.setattr(agent, "Client", lambda *args, **kwargs: BrokenClient())
    assert agent.run(["--token-file", str(token), "calendar", "create-event", "Trip", "2026-12-01", "2026-12-04",
                      "--request-id", "request-1234567890"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert "Google Calendar" in result["notice"] and "same request ID" in result["notice"]
    assert "secret-token" not in json.dumps(result)
