# AgentGate local app

The first app runs locally in your browser. It opens on **Agents**, where you can register identities, inspect expiry, and revoke access. Connections shows your Gmail account and GitHub login; Temporary access provides expiring per-agent grants. It also gives you a Gmail inbox, message reading, unsent draft creation and previews, approval buttons, access-mode control, and recent activity. Agents keep using the existing MCP endpoint or JSON commands. The app does not generate AI summaries yet. For questions and approvals by text, see [iMessage](imessage.md).

## Setup

Use your existing Gmail connection and credential/policy paths. Create a separate operator credential once, using a different file from the agent MCP token:

```bash
.venv/bin/python -m cli.commands mcp-token-create --path ~/.config/agentgate/operator-token
```

Start the app using the same environment variables as your broker launcher:

```bash
.venv/bin/python -m broker.main --app --token-file ~/.config/agentgate/mcp-token --operator-token-file ~/.config/agentgate/operator-token
```

Stop an existing broker before starting this one; use only one process per credential store. Enter the master password privately at startup. The launcher opens the app automatically. Keep the broker process running, but do your email work and approvals in the app. In app mode, terminal approvals are disabled; press Ctrl+C in the startup terminal to stop the broker. Closing the browser window does not stop the broker. `--no-open` prevents automatic browser opening.

Your existing agent commands continue to use `http://127.0.0.1:8765/mcp`. The app lives at `/app`. The operator launcher supplies its credential through a URL fragment, removes it from the address bar, and stores it in the tab's session storage. Do not share the launch link or operator file. A bare `/app` URL in a new browser session needs the operator launcher to unlock it.

## Using the app

- **Connections:** connect or disconnect Gmail and GitHub. Enter GitHub tokens privately in the local form. Disconnect is local; provider-side authorization is revoked separately. Reconnecting can replace the account used by existing agents.
- **Temporary access:** review a grant for one agent/resource and a lifetime of 1–1440 minutes; revoke it early when finished. Saved rules resume after expiry. Sends and issue creation always require approval.
- **Permissions:** select an active agent and service; set Gmail reading/drafting/sending or GitHub reading/issue creation access. Review and save in the app; see [permissions and time-window behavior](permissions.md).
- **Agents:** register a unique identity, choose its lifetime, copy the private credential-file command, and revoke access when needed. See [identity setup and migration](agents.md).
- **Inbox:** search with Gmail queries, select a message, and use “Load next page” for older results. Reading does not mark mail as read or delete anything.
- **Drafts:** create a plain-text draft with To, Cc, Bcc, subject, and body. Browse existing Gmail drafts and their previews, including older pages. Existing drafts can be edited in Gmail; this version does not edit them in the app.
- **Approvals:** agent requests appear automatically. “Review & request send” on a draft starts the same approval flow. Review the complete snapshot and click “Approve send” or “Reject”. Stale or expired requests cannot approve a later email. Attached files are listed by name/type; their contents are not displayed by the app, although Gmail’s raw MIME response includes attachment bytes inside the broker.
- **Activity:** access decisions, expiry, and operation outcomes, without email content or credentials. Refresh to see the latest results.
- **Agent access:** switch between trusted policy rules and asking for each agent operation. Every send and GitHub issue creation requires approval in both modes. The operator's own read/draft actions are authorized by operator access, independently of agent policies.

App-initiated sends use the trusted operator role and always require approval. Agent-initiated sends follow the authenticated identity’s policies. Keep a finite approval timeout configured. If an operation fails after dispatch, check Gmail and activity before another attempt; delivery can be uncertain. The original draft remains after sending, and the broker blocks further send attempts for the same draft ID.

## Local security boundary

The agent bearer credential cannot read the operator API or approve requests. The app requires a different private operator credential, validates Host/Origin headers, uses no third-party scripts/fonts, and renders email as text rather than executing HTML. All text and HTML alternatives are included in send previews; HTML is shown as source for safe review. This is a trusted local prototype: processes running as your macOS user with unrestricted filesystem access can read private credential files. It is not an OS sandbox or a multi-user service. Do not proxy it to the internet.

## Sample-data preview

```bash
.venv/bin/python examples/app_demo.py
```

The demo uses sample messages and fake sends, runs on port 8766, and never accesses Google. Its operator credential is public sample data; never use that credential for a real account.

A canceled Gmail sign-in never installs staged credentials after disconnect. Google's loopback sign-in worker may remain alive until its callback or 180-second timeout; shutdown during sign-in can wait for that worker. A credential commit already holding the provider lock finishes before shutdown and is reported as completed.
