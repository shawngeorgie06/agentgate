# Google Calendar integration

AgentGate connects one Google Calendar account with Google OAuth. Calendar has its own sign-in, separate from Gmail. You can connect a different Google account for each service, and disconnecting one does not touch the other. Both use the same OAuth client file.

The scopes are `calendar.readonly` and `calendar.events`. Tokens, the connected account, and the event-attempt ledger are stored in the encrypted credential store. MCP's `credential.request` cannot export the reserved `__agentgate:` entries.

## Google setup

1. In [Google Cloud Console](https://console.cloud.google.com/), open the project that holds your Gmail OAuth client, or follow steps 1, 3 and 4 of [Gmail setup](gmail.md#google-setup) to create one.
2. Enable the **Google Calendar API** for that project. Connecting fails until it is enabled.
3. If the consent screen lists scopes, add `calendar.readonly` and `calendar.events`. While the app is in Testing, your account must be a test user.
4. Open the AgentGate app, go to **Connections**, and select **Connect** on the Google Calendar card. Finish the Google sign-in in your browser.

The app looks for the client file at `GMAIL_CLIENT_PATH`, or `oauth-client.json` next to the credential store. The browser flow listens on a random loopback port, checks OAuth state, and uses PKCE. The app shows the connected calendar account but never the tokens. Disconnecting removes only the local credential; revoke access in your Google account settings if you also want Google to forget it.

## Tools

| Tool | Resource | Purpose |
| --- | --- | --- |
| `calendar.calendars` | `calendar:read` | Calendars the account can see, up to 250 per page |
| `calendar.events` | `calendar:read` | Events between two times, recurring events expanded and sorted by start. Up to 100 per page, over a range of at most 366 days |
| `calendar.freebusy` | `calendar:read` | Busy intervals for up to 20 calendars over at most 62 days |
| `calendar.create_event` | `calendar:write` | Create one event. Always needs approval |

Times are RFC 3339 with an offset, such as `2026-11-20T09:00:00-05:00` or `2026-11-20T14:00:00Z`. For an all-day event, give `start` and `end` as `YYYY-MM-DD`. The end date is exclusive, so a one-day event on 20 November ends on `2026-11-21`. `time_zone` is optional and takes an IANA name such as `America/New_York`. An event can last at most 31 days.

Results contain only the fields an agent needs: ID, status, title, location, link, times, organizer and attendee responses. Descriptions are cut to 2,000 characters. Conference details and other metadata are left out.

## Event creation

Every event needs your approval, in AUTO and MANUAL mode alike. The approval card shows the exact calendar and event body that will be sent. Changing the request after it is submitted has no effect.

Version 1 cannot add attendees, so no invitations are ever sent; AgentGate also passes `sendUpdates=none`. It cannot edit or delete events either.

Each request needs a stable `request_id` of 16–128 letters, numbers, underscores or hyphens. AgentGate derives the Google event ID from the agent and request ID, and records a hashed attempt in the encrypted ledger just before the single request goes to Google. If the result is uncertain, for example because the connection dropped, check Google Calendar before trying again, and reuse the same request ID. The ledger blocks a second attempt even after a restart, and Google rejects a duplicate event ID. AgentGate never retries event creation on its own.

## Agent commands

```bash
.venv/bin/python -m cli.agent --token-file /private/path/agent.token calendar calendars
.venv/bin/python -m cli.agent --token-file /private/path/agent.token calendar events 2026-11-20T00:00:00-05:00 2026-11-27T00:00:00-05:00
.venv/bin/python -m cli.agent --token-file /private/path/agent.token calendar freebusy 2026-11-20T09:00:00-05:00 2026-11-20T18:00:00-05:00
.venv/bin/python -m cli.agent --token-file /private/path/agent.token calendar create-event 'Dentist' \
  2026-11-20T09:00:00-05:00 2026-11-20T10:00:00-05:00 --request-id dentist-2026-11-20-0900
```

`create-event` also takes `--time-zone`, `--location`, `--description-file` and `--calendar-id`. `events` and `freebusy` take `--calendar-id`; `freebusy` accepts it more than once.

## Permissions

In **Permissions**, choose Google Calendar to set an agent's Read access to allow, ask or deny, and its Write access to ask or deny. Temporary access can grant `calendar:read` as allow or ask, and `calendar:write` as ask only. See [permissions](permissions.md).
