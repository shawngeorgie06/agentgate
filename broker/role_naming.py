from __future__ import annotations

import re

# Canonical naming for AgentGate-minted ephemeral PostgreSQL login roles.
#
# This is the SINGLE SOURCE OF TRUTH for the role prefix and the identifier
# pattern used as a defense-in-depth guard at every SQL sink that interpolates
# a role name into DDL text (db_broker.build_mint_statements, the reaper's
# namespace filter in db_broker.reap, and db_executor.drop_role). Postgres DDL
# takes no bind parameters, so these guards are the last line preventing a
# role name from carrying anything but [0-9a-f] hex.
#
# It lives in a leaf module — imported by both db_broker and db_executor, and
# importing neither — so the two sinks can never drift onto divergent patterns.
# ALWAYS match with `.fullmatch` (the pattern is deliberately unanchored; a
# `.match` would only anchor the start and admit trailing injection).
ROLE_PREFIX = "agentgate_"

ROLE_RE = re.compile(r"agentgate_[0-9a-f]+")
