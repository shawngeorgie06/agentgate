# AgentGate AWS Broker — Design

**Date:** 2026-07-06
**Status:** Approved
**Depends on:** V1 core (auth/policy/escalation/audit/MCP spine), infra-broker patterns (2026-07-02 DB spec, 2026-07-05 SSH spec)

## Problem

Agents need AWS access — reading S3, querying DynamoDB, invoking Lambdas — but handing an agent a long-lived access key is a standing credential with unbounded lifetime. The DB and SSH brokers solved this shape for PostgreSQL and servers; this subsystem solves it for AWS using the platform's native short-lived credential mechanism, STS AssumeRole.

## Decision summary

| Decision | Choice |
|---|---|
| Mechanism | **STS AssumeRole**: broker assumes an operator-registered IAM role and returns the temporary keypair + session token |
| Broker's own credential | **Dedicated IAM user's access key, stored encrypted** (Argon2id + AES-256-GCM). The user's IAM policy allows ONLY `sts:AssumeRole` on the registered role ARNs — setup docs show the exact policy JSON |
| Scoping | **The IAM role carries the scope.** A resource is name + role ARN + region + optional ExternalId; permissions are authored in IAM (the native, reviewable place). No inline session policies in V2 (opaque JSON AgentGate cannot meaningfully validate) |
| Traceability | `RoleSessionName = agentgate-<agent>-<resource>` — every AWS action shows the agent in CloudTrail |
| Expiry | `DurationSeconds = AWS_CRED_TTL_MINUTES × 60` (default 15 — also the STS minimum of 900s); STS credentials expire natively — **no reaper** |
| Revocation before expiry | Out of scope (AWS offers none short of revoking all of a role's sessions); TTL is the control — documented |
| STS client | **boto3, lazy-imported** behind an injectable `StsExecutor` protocol (the asyncpg pattern); real call wrapped in `asyncio.to_thread` so the event loop never blocks. Unit tests use a fake — network-free |
| Policy engine | **Unchanged.** The resource name occupies the credential slot |

Rejected alternatives: hand-rolled SigV4 over httpx (no new dependency, but hand-writing request-signing crypto in a security tool invites subtle bugs; boto3 is battle-tested); ambient AWS credential chain (on a laptop it silently picks up whatever admin profile exists — the opposite of least privilege); session policies / policy templates (either opaque JSON or an opinionated policy library to maintain — scope creep).

## Architecture

One-time operator setup (documented in the README with exact IAM JSON):

1. Create IAM roles for the tasks agents need (e.g. `agent-s3-reader`), scoped in IAM.
2. Create a dedicated IAM user (e.g. `agentgate-broker`) whose only policy is `sts:AssumeRole` on those role ARNs; create an access key for it.
3. `agentgate aws-key-set <access_key_id>` — the secret key is read from `AGENTGATE_AWS_SECRET_KEY`, else getpass (TTY), else stdin — never argv. Stored encrypted.
4. `agentgate aws-add s3-reader --role-arn arn:aws:iam::123456789012:role/agent-s3-reader --region us-east-1 [--external-id X]` — registers a resource. ARN/region/external-id validated at add time.

Grant flow:

```
agent → aws_credential_request(agent, agent_key, resource)
  → _authenticate            unknown agent → audited deny; never escalates
  → MANUAL mode              → escalate to operator [y/n] (flood cap; timeout → expired)
  → policy evaluate          resource name in the credential slot (globs, hard-deny)
  → _grant_aws:
      resources.get(name)    KeyError → "unknown aws resource" deny;
                             other store error → audited generic deny
      key_store.load()       missing → audited deny "aws broker key not set";
                             decrypt failure → audited generic deny
      aws_broker.assume_role validates role_arn / session name / external_id at the
                             sink, then calls STS via the executor (asyncio.to_thread);
                             ANY STS/validation/network error → audited generic deny
                             ("could not assume role for '<resource>'" — never the
                             boto3 exception text, which can embed ARNs/request IDs)
  → audit approved (role_arn, token_expiry = expiration — never secrets)
  → {granted: true, access_key_id, secret_access_key, session_token,
     expiration, region, reason}
```

Denial response shape (all denials, fail closed): `{granted: false, access_key_id: null, secret_access_key: null, session_token: null, expiration: null, region: null, reason}`.

Session name: `agentgate-<agent>-<resource>`, re-validated at the sink against the STS charset `[\w+=,.@-]{2,64}` with `.fullmatch`. If the combined name exceeds 64 characters it is truncated to 64 (documented); if after truncation it still fails validation (e.g. an agent name with characters outside the STS charset), the request is denied generically — no unvetted value ever reaches the STS call.

## Components

| Unit | Responsibility |
|---|---|
| `broker/aws_validation.py` | Leaf module (imports only `re`): `AwsValidationError(ValueError)`; `ROLE_ARN_RE` (`arn:aws:iam::\d{12}:role/[\w+=,.@/-]+`), `SESSION_NAME_RE` (`[\w+=,.@-]{2,64}`), `EXTERNAL_ID_RE` (`[\w+=,.@:/-]{2,1224}`), `REGION_RE` (`[a-z]{2}(-[a-z]+)+-\d`); `validate_role_arn`, `validate_session_name`, `validate_external_id`, `validate_region`. All matching via `.fullmatch` (patterns unanchored). Non-str input raises `AwsValidationError`, never TypeError |
| `broker/aws_key_store.py` | EncryptedStore subclass holding the broker's IAM access key: `set(access_key_id, secret_access_key)` (secret encrypted; overwriting an existing key is allowed — key rotation is routine, unlike re-keying a CA), `load() -> AwsBrokerKey` (KeyError if absent), `is_set() -> bool`. `AwsBrokerKey(access_key_id, secret_access_key)` frozen dataclass, secret `field(repr=False)` |
| `broker/aws_resource_store.py` | `AwsResource(name, role_arn, region, external_id: str \| None, created_at)` — nothing secret. EncryptedStore base with no encrypted fields (0600 perms, atomic writes, per-access re-read — the SshResourceStore precedent). `store/get/delete/list_names/list_metadata` (metadata = full record) |
| `broker/aws_executor.py` | `StsExecutor(Protocol)` with `async assume_role(access_key_id, secret_access_key, *, role_arn, session_name, duration_seconds, region, external_id) -> dict` returning `{access_key_id, secret_access_key, session_token, expiration}` (expiration as UTC ISO string). `Boto3StsExecutor`: lazy `import boto3` inside the method; the synchronous `sts.assume_role` call wrapped in `asyncio.to_thread`; client constructed per call with exactly the broker key (never the ambient chain) |
| `broker/aws_broker.py` | `build_session_name(agent, resource) -> str` (compose, truncate to 64, sink-validate); `async assume_role(executor, key, resource, ttl_minutes, session_name) -> AwsCred` — re-validates role_arn/region/external_id at the sink before the call. `AwsCred(access_key_id, secret_access_key, session_token, expiration, region)` frozen dataclass, secret fields `field(repr=False)` |
| `broker/mcp_server.py` | `request_aws_credentials` / `_grant_aws` / `_escalate_aws` / `_aws_deny`, transcribed from the ssh path; `Broker.__init__` gains `aws_resources`, `aws_key`, `aws_executor` (all default None; None → fail-closed deny). MCP tool `aws_credential_request` — 9 tools total, 6 grant-or-change |
| `broker/audit.py` | `log(...)` gains `role_arn: str \| None = None`, included only when not None (the scopes/username/grants/key_id pattern) |
| `broker/config.py` | `AWS_KEY_PATH` (default `<home>/aws_key.json`), `AWS_RESOURCES_PATH` (default `<home>/aws_resources.json`), `AWS_CRED_TTL_MINUTES` (default 15, int ≥ 15 — the STS floor of 900 seconds; a value below the floor would just make STS reject every call) |
| `cli/commands.py` | `aws-key-set <access_key_id>` (secret via env → getpass → stdin, never argv; rejects empty secret with exit 2; audited `log_operator(action="aws-key-set", subject="aws-broker-key")` — never the key values), `aws-add`, `aws-list`, `aws-remove` (validation failures → exit 2 nothing stored; unknown remove → exit 1 no audit row) |
| `broker/main.py` | `build_broker` wires `AwsResourceStore` + `AwsKeyStore` + `Boto3StsExecutor`. No reaper |
| deps | `boto3>=1.34` added to `requirements.txt` + `pyproject.toml` (lazy-imported — the broker runs without it until an AWS grant is attempted; an ImportError surfaces as the generic audited deny) |

## Security model

- **Residual risk (documented honestly):** AgentGate holds an IAM access key that can assume every registered role. Mitigations: the key belongs to a dedicated user allowed only `sts:AssumeRole` on the specific registered ARNs (exact policy JSON in the README); encrypted at rest under the master password; every assumption lands in CloudTrail with `agentgate-<agent>-<resource>` as the session name.
- **No pre-expiry revocation** of issued STS credentials (AWS offers none short of revoking all sessions on the role via a deny policy); TTL is the control. Stated in the README beside the residual-risk note.
- **Validate at input AND sink:** role ARN, region, and external ID validated at `aws-add`; role ARN, region, external ID, and session name re-validated inside `aws_broker.assume_role` before any STS call. The agent supplies only the resource name (a dict key); the session name embeds the authenticated agent name and is sink-checked against the STS charset regardless.
- **Secret hygiene:** the issued `secret_access_key`/`session_token` appear only in the tool response; the broker's own secret key is encrypted at rest, `repr=False` in every dataclass carrying it, never in argv/stdout/audit/reasons. `aws-list` prints resource metadata only (nothing secret exists in a resource). Audit on grant records `role_arn` and expiry only. boto3 exception text (which can embed ARNs, request IDs, and endpoint details) never reaches a `reason` or the audit.
- **Fail-closed paths:** unauthenticated, flood cap, policy hard-deny, escalation timeout/denial, unknown resource, broker key not set, key decrypt failure, resource store failure, validation failure at the sink, STS/network error, boto3 not installed — each writes an audited `decision="denied"` (or `"expired"`) row and returns the full null-field shape with a generic reason.
- **Ambient-chain exclusion:** `Boto3StsExecutor` constructs its client with explicit `aws_access_key_id`/`aws_secret_access_key` arguments only — it must never fall back to the default credential chain (env vars, ~/.aws, instance profile).

## Error handling

| Failure | Behavior |
|---|---|
| Broker key not set (`aws-key-set` never run) | Audited deny, reason `"aws broker key not set"` |
| Key store decrypt failure | Audited deny, generic reason |
| Unknown resource name | Audited deny, `"unknown aws resource '<name>'"` |
| Resource store failure (non-KeyError) | Audited deny, generic reason |
| Sink validation failure (bad ARN/region/external-id/session name) | Audited deny, generic `"could not assume role for '<name>'"` |
| STS error (AccessDenied, MaxSessionDuration exceeded, network, boto3 missing) | Audited deny, `"could not assume role for '<name>'"` — never the exception text |
| `aws-key-set` with empty secret | Exit 2, nothing stored, no audit row |
| `aws-add` invalid ARN/region/external-id | Exit 2, nothing stored, no audit row |
| `aws-remove` unknown name | Exit 1, stderr message, no audit row |

## Testing

- **Validation (`tests/test_aws_validation.py`):** fullmatch discipline (trailing newline rejected), charset edges, non-str → AwsValidationError, ARN account-id shape, session-name length bounds.
- **Broker unit (`tests/test_aws_broker.py`):** `build_session_name` composition/truncation/sink-rejection; `assume_role` against a `FakeStsExecutor` asserting the EXACT parameters passed (RoleArn, RoleSessionName, DurationSeconds = ttl×60, ExternalId present iff configured, region) and that secrets never appear in reprs.
- **Stores (`tests/test_aws_key_store.py`, `tests/test_aws_resource_store.py`):** secret encrypted on disk (raw file lacks it), set-overwrite allowed, load-absent raises KeyError; resource CRUD + full metadata.
- **Broker path (`tests/test_aws_tool.py`):** transcribed from `test_ssh_tool.py` — every denial path audits + full null shape; auth strictly before escalation; secrets never in the audit file (marker strings); key-not-set and decrypt/store/STS failures fail closed generically; tool registered as exactly `aws_credential_request`.
- **CLI (`tests/test_aws_cli.py`):** key-set secret never argv + empty-secret rejection; add/list/remove happy paths, validation failures, operator audit rows (never key values).
- **Config:** defaults, overrides, TTL ≥ 15.
- **Integration (skip-gated on `AGENTGATE_TEST_AWS_ROLE_ARN`, using ambient TEST credentials via env for the broker key):** real AssumeRole succeeds; returned credentials work (`sts get-caller-identity` shows the assumed-role ARN containing the agentgate session name); a wrong ExternalId is refused by STS.

## Out of scope (V2)

Inline session policies / policy templates; ambient credential chain; IAM Roles Anywhere / OIDC federation; automatic broker-key rotation; per-grant source-IP conditions; non-AssumeRole STS APIs (GetFederationToken, GetSessionToken); revoking issued sessions.
