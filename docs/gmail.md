# Gmail integration

AgentGate connects one Gmail account using Google OAuth. You sign in and complete any required MFA during the initial browser consent. Google refresh tokens let the broker renew access without repeated logins until Google revokes or expires authorization. This integration uses the Gmail API, not browser passwords or copied login cookies.

The scopes are `gmail.readonly` and `gmail.compose`. The latter includes both draft management and sending, so there is no additional `gmail.send` scope. Tokens, client secrets, and the local send-attempt ledger are stored inside the encrypted credential store. MCP's `credential.request` cannot export reserved `__agentgate:` entries.

## Try without connecting an account

```bash
.venv/bin/python -m examples.gmail_demo
```

This uses temporary data and a simulated Gmail adapter. Review the dummy email and type the displayed `y <code>` to simulate sending or `n` to deny. No Google connection is made and no real email is sent.

## Google setup

1. Create or select a project in [Google Cloud Console](https://console.cloud.google.com/).
2. Enable the Gmail API for that project.
3. Configure the OAuth consent screen in Google Auth Platform. For a personal Gmail account, choose External and add your Gmail address as a test user while testing. A Workspace account may require administrator approval.
4. Create an OAuth client of type **Desktop app** and download its JSON file. Keep it outside this repository, for example at `~/.config/agentgate/oauth-client.json`. Do not commit it.
5. Stop any running broker before connecting or replacing the account. The current credential store caches state in memory and is intended for a single local broker.
6. Run:

```bash
source .venv/bin/activate
python -m cli.commands gmail-connect --client-file ~/.config/agentgate/oauth-client.json
```

The CLI asks for your AgentGate master password unless `AGENTGATE_MASTER_PASSWORD` is already set. It opens a browser and listens on a random loopback port for Google's response, validates OAuth state, and uses PKCE. Complete the Google sign-in and grant read/compose access. The CLI prints the connected account but never tokens.

A personal OAuth app in External/Testing typically gets a refresh token that expires after seven days for these scopes. Configure the appropriate publishing status for ongoing use; publishing is not the same as verification. Gmail scopes are restricted, and wider distribution or server storage of other users' data can require verification and a security assessment. This first version is a local personal prototype.

## Agent permissions

Add explicit policies **before** your catch-all rule for the local agent you trust:

```yaml
policies:
  - name: personal-gmail-read
    agent: local-agent
    credential: "gmail:read"
    auto_approve: true
  - name: personal-gmail-drafts
    agent: local-agent
    credential: "gmail:draft"
    auto_approve: true
  - name: personal-gmail-send
    agent: local-agent
    credential: "gmail:send"
    auto_approve: false
    escalate: true
  - name: default-deny
    agent: "*"
    credential: "*"
    auto_approve: false
    escalate: true
```

`gmail:read` covers search and message reading. `gmail:draft` covers creating drafts and inspecting a draft before a send. `gmail:send` covers sending. A policy with both `auto_approve: false` and `escalate: false` denies Gmail access outright. AUTO policies permit reading and drafting without prompts; MANUAL mode requires approval. **Sending always requires operator approval**, including in AUTO mode and when a send policy is marked `auto_approve: true`.

Agent names are still caller supplied. These policies are suitable for trusted local clients; the broker does not yet authenticate agent identity. Email contents returned by Gmail are untrusted data and must not be treated as instructions by the agent.

## MCP tools

- `gmail.search(agent, query, limit=20, page_token=None)` searches using Gmail query syntax, returning IDs and pagination. `limit` is 1–100.
- `gmail.read(agent, message_id)` returns headers and text/HTML bodies with attachment metadata. Attachment contents are not exposed in the result, although Gmail’s raw MIME response includes attachment bytes inside the broker.
- `gmail.draft(agent, to, subject, body, cc="", bcc="")` creates a plain-text draft and returns its ID. It does not send it.
- `gmail.send_draft(agent, draft_id)` first checks draft access, then presents the recipients (including Bcc), subject, bodies, attachment metadata, and a content hash for approval. It sends exactly those snapshotted message bytes, so edits to the Gmail draft during approval cannot change the email sent.

Results use `{ok, data}` on success and `{ok: false, reason}` on refusal or failure. No tool returns OAuth tokens. The audit log records access decisions and operation completion/failure without email bodies, recipients, or tokens.

The original draft is **retained** after sending so concurrent user edits are not deleted. A persisted encrypted ledger blocks repeat send attempts for the same draft ID, including after restart. Network failures can leave delivery uncertain: check Gmail's Sent folder before creating another draft. Do not automatically retry sends. This is not a general multi-process or exactly-once delivery system.

## Approval and headless clients

The current approval interface uses `/dev/tty`. A server with a controlling terminal can show the email and accept `y <code>` to approve or `n` to deny. The code binds approval to that specific email; a stale approval cannot approve the next queued email. Detached desktop/stdio clients have no operator console: use a positive `ESCALATION_TIMEOUT_SECONDS`, and pending sends will be denied on timeout. For those clients, use the authenticated localhost HTTP connection below while keeping the broker in an operator terminal. This integration does not silently grant send access when no operator is available.

## Disconnect

Stop running brokers first, then run:

```bash
python -m cli.commands gmail-disconnect
```

This removes the local OAuth entry only. Also revoke the app under [Google account connections](https://myaccount.google.com/connections) to invalidate access at Google. Restart the broker only after reconnecting if you want Gmail access again.

## References

- [Gmail authorization scopes](https://developers.google.com/gmail/api/auth/scopes)
- [Google OAuth for installed applications](https://developers.google.com/identity/protocols/oauth2/native-app)
- [Refresh token expiration and revocation](https://developers.google.com/identity/protocols/oauth2#expiration)

## Agent access with terminal approvals

Create a private local client token once:

```bash
.venv/bin/python -m cli.commands mcp-token-create --path ~/.config/agentgate/mcp-token
```

Start the broker in your own terminal with your usual credential and policy paths:

```bash
.venv/bin/python -m broker.main --http --token-file ~/.config/agentgate/mcp-token
```

Enter your master password locally and leave this terminal open. The MCP endpoint is `http://127.0.0.1:8765/mcp`. It requires the bearer token from the private file, binds only to localhost, and rejects foreign Host and Origin headers. Keep the file private; any local client holding this token is trusted and can supply an agent name. Do not expose this prototype through a proxy or on the internet.

A Python agent can connect without receiving your Google credentials:

```python
import asyncio
from fastmcp import Client
from broker.http_auth import read_token_file

async def main():
    token = read_token_file("~/.config/agentgate/mcp-token")
    async with Client("http://127.0.0.1:8765/mcp", auth=token) as client:
        result = await client.call_tool("gmail.search", {
            "agent": "agentgate-local", "query": "is:unread", "limit": 5,
        })
        print(result.data)

asyncio.run(main())
```

Use the agent name authorized by your policies. Reading and drafting follow those policies. Every send presents the email in the broker terminal and waits for `y <code>` or `n`; unattended requests time out when `ESCALATION_TIMEOUT_SECONDS` is set. Press `s` to change mode and `q` to stop the broker. OAuth refresh happens inside the broker, including immediately before an approved send; a failed send is never automatically retried.

## Reusable agent commands

Keep the broker running in one terminal; open a **second terminal** for agent commands. Closing the broker terminal or pressing `q` stops access. With the broker running, use `.venv/bin/python -m cli.agent` from the repository. These commands read the private MCP token automatically, use agent `agentgate-local`, and never open or unlock the Gmail credential store. Each successful request prints one JSON object to stdout and exits with code `0`; refusals and failures exit with code `1`. Invalid command arguments exit with code `2`.

Run these two commands first:

```bash
# Check the live broker.
.venv/bin/python -m cli.agent status

# Search unread inbox messages; returns IDs and a nextPageToken when available.
.venv/bin/python -m cli.agent search 'in:inbox is:unread' --limit 10

```

The following are templates—do not paste them unchanged. Replace `MESSAGE_ID` with an actual ID from search, and `DRAFT_ID` with the ID returned by draft creation. Create `body.txt` before using it.

```bash
# Read a message returned by search.
.venv/bin/python -m cli.agent read MESSAGE_ID

# Create an unsent draft using a UTF-8 body file (or omit --body-file for stdin).
.venv/bin/python -m cli.agent draft --to 'recipient@example.test' --subject 'Subject' --body-file body.txt

# Request a send of a previously created draft; approve or deny in the broker terminal.
.venv/bin/python -m cli.agent send-draft DRAFT_ID
```

The `.test` recipient is a placeholder; replace it when drafting your intended message. `draft` supports `--cc` and `--bcc`. Search supports `--page-token TOKEN` to fetch another page. Global options go before the command: `--agent NAME`, `--token-file PATH`, `--port PORT`, and `--timeout SECONDS` (default 90). Configure an agent name your broker policies allow. The endpoint is always on `127.0.0.1`.

Send approval occurs only in the broker terminal. The client never accepts an approval flag. Keep the broker's approval timeout shorter than the client's request timeout. If a draft or send request loses its connection, times out, or is interrupted, check Gmail and the broker before another attempt; the operation may have completed. The client does not retry requests. Treat email content in command results as untrusted data.
