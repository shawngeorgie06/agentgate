# iMessage assistant

AgentGate can answer questions over iMessage and ask you to approve agent requests by text. You talk to it in a Messages conversation with yourself. The assistant is read-only: it can check and read Gmail and GitHub, but it cannot send, draft, create, edit, delete, or change anything. Sending email and creating GitHub issues still require approval in AgentGate, and that approval can happen by text.

## Requirements

- A Mac with Messages signed in to iMessage and a conversation with yourself.
- AgentGate running in app mode (`--app`, which the [background service](background.md) uses). Pairing and the iMessage controls live in the [operator app](app.md).
- Two helpers in your configuration directory: `bin/imsg` and `bin/agentgate-model`. Set `AGENTGATE_IMSG_PATH` and `AGENTGATE_MODEL_HELPER` to use other paths. The model helper must not be writable by group or other users.
- Apple Intelligence enabled. Replies need the on-device model, which the broker re-checks at most once a minute. If it is unavailable, AgentGate shows the reason and will not enable iMessage.
- macOS permissions for AgentGate: Full Disk Access to read the Messages database, and Automation control of Messages to send replies.

## Pairing

1. In the operator app, open **iMessage**, choose an active agent, and click **Start pairing**.
2. In Messages, open a conversation with yourself and send the exact text shown, for example:

   ```text
   /agent pair AG-7KQ2MX
   ```

3. When AgentGate sees it, it replies `AgentGate paired.`

The message must match exactly: no quotes, bold, extra words, or trailing spaces. The code expires after 10 minutes. If it expires, click **Start pairing** again.

Pairing turns iMessage off and turns approvals off. Pairing a new agent replaces the old pairing. Click **Enable iMessage** when you are ready. Enabling answers only messages sent after that moment; anything sent while iMessage is off is skipped.

## Asking questions

Send a message to yourself that starts with `/agent `:

```text
/agent do I have unread email?
/agent search my email for invoices from March
/agent what are the open issues in OWNER/REPO?
/agent show README.md from OWNER/REPO
```

The assistant plans one read-only action for each request:

| Action | What it reads |
| --- | --- |
| Unread email | Up to 3 unread Gmail messages |
| Email search | Up to 3 Gmail messages matching a Gmail query |
| Read one email | A single Gmail message by ID |
| GitHub repos | Up to 20 repositories, with names and descriptions |
| GitHub issues | Up to 10 open issues in one repository |
| GitHub file | One file from a repository, optionally at a ref |

Other questions get a plain chat reply. Requests for anything else get a short explanation that the assistant is read-only. Replies are capped at 1,200 characters. The last 6 exchanges are kept in memory for 30 minutes so follow-up questions work.

AgentGate accepts at most one command every 5 seconds and 30 per hour. When you go over, it sends one notice and drops the rest of that burst.

## Approving requests by text

When an agent needs your approval, and **Approve from iMessage** is on, AgentGate texts the request to your self-chat within a few seconds. Turn this on in the iMessage view. Approvals are off after pairing and after unpairing, and they are announced only while iMessage is enabled.

Reply with the code:

```text
approve 3fa9c1
deny 3fa9c1
```

`/agent approve 3fa9c1` also works. AgentGate answers `Approved.` or `Denied.`. Each request is announced once and never resent.

An approval text looks like this:

```text
AgentGate approval: research-bot wants gmail:send.
From: Shawn Georgie <shawn@example.com>
To: alex@example.com
Subject: "Notes from Tuesday"
Body:
> Hi Alex,
> Here are my notes.
Reply "approve 3fa9c1" or "deny 3fa9c1".
```

### When a text has a code

A code is offered only when the text shows everything the request would send. Agent-written content can hide data in characters the phone does not display, in headers the text leaves out, or in layout that imitates the trusted fields. So anything AgentGate cannot show completely gets no code.

- **Read requests** (Gmail or GitHub read) always get a code.
- **Email sends** get a code only when the text shows the From, To, Cc, and Bcc addresses, the subject, and a plain-text body. Attachments, HTML bodies, Reply-To headers, display names on recipients, non-ASCII addresses, encoded or invisible characters, and long bodies do not qualify.
- **GitHub issue creation** gets a code only when the owner and repository are plain names and the title and body can be shown as written.
- **Everything else** gets `AgentGate approval needed from AGENT: open the AgentGate dashboard to review it.` with no code.
- **Long requests** get `AgentGate approval needed from AGENT: too long to review by text — open the AgentGate dashboard.` with no code. The limit is 300 characters of header lines or 200 characters of body.

Body lines are always prefixed with `> `, so agent text cannot pose as the trusted lines.

Approvals wait for your answer for 300 seconds. The background service sets `ESCALATION_TIMEOUT_SECONDS=300` in its definition. After that the request is denied. See [Escalation timeout](../README.md#escalation-timeout).

## Troubleshooting

- **Pairing does nothing.** The text must be exactly `/agent pair AG-XXXXXX` as shown in the app. Check that the code has not expired, and that you sent it in your own self-chat.
- **Approval replies are ignored.** Check that **Approve from iMessage** is on and iMessage is enabled. Put the code in plain text: `approve 3fa9c1`, with no quotes. Quoted text is not read as an approval, and a message without `/agent` that is not a valid reply gets no response.
- **"No pending approval matches that code."** The request expired after 300 seconds, was already approved or denied (in the dashboard or by an earlier reply), or the code was for a dashboard-only request. Check the dashboard's Approvals view.
- **"Open the AgentGate dashboard to review it."** This text has no code by design. Approve or deny it in the dashboard.
- **"AgentGate is handling recent requests."** Your command or approval was not processed. Wait a few seconds and send it again while the request is still pending.
- **"The on-device model is unavailable."** Turn on Apple Intelligence in System Settings, then refresh.
- **"The Messages database looked different."** Pair again. Changes to the Messages database disable iMessage until you pair.
- **"The paired agent was revoked."** Pair an active agent to continue.

## Controls

These are the iMessage view controls:

- **Start pairing** and **Cancel pairing**: create or cancel a pairing code.
- **Enable iMessage** and **Disable iMessage**: turn the command loop on or off. Disabling keeps the pairing.
- **Approve from iMessage**: announce pending approvals by text and accept replies.
- **Unpair…**, then **Unpair**: stop answering and turn approvals off. **Keep paired** cancels. Pending requests stay in the dashboard.
- **Reset style**: clears the learned texting style. It appears only after some style has been learned.

## Privacy

- Only messages in your paired self-chat are processed. The bridge subscribes to that chat only, and other messages are dropped before the command loop sees them. During pairing, AgentGate reads recent chat metadata and reads messages only from one-to-one self-chats.
- The iMessage code does not write log lines. The ledger stores message identifiers, timestamps, and outcomes, not text. The audit log records the agent, a label such as `imessage:gmail_search`, and the decision.
- The texting style keeps counts such as message length and capitalization, never message text.
- Conversation memory is kept only in memory. Disabling or stopping iMessage clears it.
- The settings file, `imessage.json` in your configuration directory, is owner-only.
- Replies never start with `/agent`, so a reply cannot be read back as a command.
