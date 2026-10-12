# Agent permissions in the app

Open **Permissions**, select an active enrolled agent, and review its Gmail access. This version manages the single connected Gmail account; it does not edit legacy API-key access or provide multiple-account selection.

- **Read:** allow searches and reading without asking in AUTO mode, ask for each operation, or deny.
- **Draft:** allow creating/inspecting drafts without asking in AUTO mode, ask each time, or deny.
- **Send:** ask before every send, or deny. Automatic sending is unavailable. Sending also requires draft access to inspect the message; denying drafts prevents sending.

Click **Review changes**, read the agent name and settings, then **Save permissions**. Your own operator access remains separate. Revoked or expired agents cannot have their permissions edited, and a permission save never reactivates an identity.

## Existing rules and time windows

The initial selections reflect policy evaluation at the current time. Saving creates three explicit, all-time Gmail rules for the selected agent, ahead of earlier rules. Other agents and unrelated rules are retained; earlier rules for this agent remain in the file but the saved Gmail rules take precedence. YAML formatting/comments may be rewritten.

If matching time-window rules exist, the app lists them and leaves all three new choices unselected. Choose each setting explicitly and acknowledge replacing time-window restrictions with all-time rules. The save API also requires that acknowledgement. The review dialog describes the all-time effect. This editor does not create schedules; keep scheduled access in YAML if needed instead of saving all-time replacements.

AUTO mode follows the saved choices. MANUAL mode still asks for allowed reading and drafting; Deny stays denied. Every send requires approval in both modes.

## Changes take effect immediately

A save reloads the running policy engine and cancels pending agent requests. Operations waiting for Gmail's provider lock or token refresh check policy revision again before dispatch. This prevents old authorization from bypassing new Deny or Ask settings. Agents can submit a fresh request afterward. Pending operator requests are not canceled by agent permission changes.

Saving also invalidates stale agent policy proposals, including proposals approved just before the new permission save. A stale permission form returns a conflict; reload and review before saving again. An operation already dispatched cannot be undone by changing a policy.

## Storage and authorization

Settings persist as marked rules in the existing `POLICIES_PATH` YAML file. Saving the same agent again replaces its previously managed rules, preventing duplicates. Candidate rules are validated before atomic replacement. The broker retains one process per provider store; this is not a distributed policy database.

Only the independent operator credential can inspect or modify permissions. Agent credentials cannot call these endpoints, and client-supplied agent names do not change authenticated identity. Successful and failed permission updates appear in Activity without credential values or email content.
