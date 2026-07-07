import json
from broker.audit import AuditLogger


def test_log_appends_jsonl_entry(tmp_path):
    path = str(tmp_path / "audit.log")
    logger = AuditLogger(path)
    logger.log(
        agent="claude-code",
        credential_requested="anthropic-api-key",
        policy_matched="cc-anthropic",
        decision="approved",
        mode="auto",
        token_expiry="2026-06-24T23:14:00",
    )
    lines = (tmp_path / "audit.log").read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["agent"] == "claude-code"
    assert entry["credential_requested"] == "anthropic-api-key"
    assert entry["policy_matched"] == "cc-anthropic"
    assert entry["decision"] == "approved"
    assert entry["mode"] == "auto"
    assert entry["token_expiry"] == "2026-06-24T23:14:00"
    assert "timestamp" in entry


def test_log_appends_multiple_entries(tmp_path):
    path = str(tmp_path / "audit.log")
    logger = AuditLogger(path)
    logger.log(agent="a", credential_requested="k", policy_matched="default-deny",
               decision="denied", mode="auto", token_expiry=None)
    logger.log(agent="b", credential_requested="k2", policy_matched="p",
               decision="escalated", mode="manual", token_expiry=None)
    lines = (tmp_path / "audit.log").read_text().strip().splitlines()
    assert len(lines) == 2


def test_log_never_contains_token_value(tmp_path):
    # The log() signature has no token-value parameter — only token_expiry.
    import inspect
    params = inspect.signature(AuditLogger.log).parameters
    assert "token" not in params
    assert "credential_value" not in params


def test_log_accepts_expired_decision(tmp_path):
    path = str(tmp_path / "audit.log")
    logger = AuditLogger(path)
    logger.log(
        agent="claude-code",
        credential_requested="anthropic-api-key",
        policy_matched="cc-anthropic",
        decision="expired",
        mode="auto",
        token_expiry=None,
    )  # must not raise
    entry = json.loads((tmp_path / "audit.log").read_text().strip().splitlines()[-1])
    assert entry["decision"] == "expired"


def test_log_operator_records_mutation_without_values(tmp_path):
    path = tmp_path / "audit.log"
    logger = AuditLogger(str(path))
    logger.log_operator(action="cred-store", subject="anthropic-api-key")
    entry = json.loads(path.read_text().strip())
    assert entry["actor"] == "operator"
    assert entry["action"] == "cred-store"
    assert entry["subject"] == "anthropic-api-key"
    assert "timestamp" in entry
    # Shape carries no slot for a value or key.
    assert set(entry) == {"timestamp", "actor", "action", "subject"}


def test_audit_includes_scopes_when_provided(tmp_path):
    import json
    from broker.audit import AuditLogger

    path = tmp_path / "audit.log"
    logger = AuditLogger(str(path))
    logger.log(
        agent="claude-code", credential_requested="work", policy_matched="p",
        decision="approved", mode="auto", token_expiry="2026-06-27T11:00:00",
        scopes=["openid", "email"],
    )
    entry = json.loads(path.read_text(encoding="utf-8").strip())
    assert entry["scopes"] == ["openid", "email"]


def test_log_accepts_username_and_grants(tmp_path):
    import json
    from broker.audit import AuditLogger
    path = tmp_path / "audit.log"
    AuditLogger(str(path)).log(
        agent="claude-code", credential_requested="analytics-ro", policy_matched="p",
        decision="approved", mode="auto", token_expiry="2026-07-02T10:15:00+00:00",
        username="agentgate_ab12", grants=['GRANT SELECT ON "public"."events" TO "agentgate_ab12"'],
    )
    entry = json.loads(path.read_text().strip())
    assert entry["username"] == "agentgate_ab12"
    assert entry["grants"] == ['GRANT SELECT ON "public"."events" TO "agentgate_ab12"']


def test_log_omits_username_grants_when_absent(tmp_path):
    import json
    from broker.audit import AuditLogger
    path = tmp_path / "audit.log"
    AuditLogger(str(path)).log(
        agent="a", credential_requested="k", policy_matched="p",
        decision="denied", mode="auto", token_expiry=None,
    )
    entry = json.loads(path.read_text().strip())
    assert "username" not in entry and "grants" not in entry


def test_log_accepts_key_id(tmp_path):
    import json
    from broker.audit import AuditLogger
    path = tmp_path / "audit.log"
    AuditLogger(str(path)).log(
        agent="claude-code", credential_requested="web-1", policy_matched="p",
        decision="approved", mode="auto", token_expiry="2026-07-05T10:15:00+00:00",
        username="deploy", key_id="agentgate:claude-code:web-1",
    )
    entry = json.loads(path.read_text().strip())
    assert entry["key_id"] == "agentgate:claude-code:web-1"


def test_log_omits_key_id_when_absent(tmp_path):
    import json
    from broker.audit import AuditLogger
    path = tmp_path / "audit.log"
    AuditLogger(str(path)).log(
        agent="a", credential_requested="k", policy_matched="p",
        decision="denied", mode="auto", token_expiry=None,
    )
    assert "key_id" not in json.loads(path.read_text().strip())
