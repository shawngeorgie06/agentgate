from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import List, Optional

import yaml

_REQUIRED_FIELDS = ("name", "agent", "credential", "auto_approve")


class PolicyError(Exception):
    """Raised when the policy file is malformed or fails schema validation."""


@dataclass(frozen=True)
class Decision:
    policy_name: str
    auto_approve: bool
    escalate: bool


def _parse_hhmm(value: str) -> datetime.time:
    hh, mm = value.split(":")
    return datetime.time(int(hh), int(mm))


def _in_window(now: datetime.time, start: datetime.time, end: datetime.time) -> bool:
    if start <= end:
        return start <= now <= end
    # Window wraps past midnight (e.g. 22:00–06:00).
    return now >= start or now <= end


class PolicyEngine:
    def __init__(self, policies: List[dict]) -> None:
        self._policies = policies

    @classmethod
    def from_file(cls, path: str) -> "PolicyEngine":
        errors = cls.validate_file(path)
        if errors:
            raise PolicyError("; ".join(errors))
        with open(path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        return cls(doc["policies"])

    @staticmethod
    def validate_file(path: str) -> List[str]:
        errors: List[str] = []
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
        except (OSError, yaml.YAMLError) as exc:
            return [f"could not parse policy file: {exc}"]

        if not isinstance(doc, dict) or "policies" not in doc:
            return ["policy file must have a top-level 'policies' list"]
        if not isinstance(doc["policies"], list):
            return ["'policies' must be a list"]

        for i, pol in enumerate(doc["policies"]):
            if not isinstance(pol, dict):
                errors.append(f"policy #{i} is not a mapping")
                continue
            for field in _REQUIRED_FIELDS:
                if field not in pol:
                    errors.append(f"policy '{pol.get('name', i)}' missing required field '{field}'")
            tw = pol.get("time_window")
            if tw is not None:
                if not isinstance(tw, dict) or "start" not in tw or "end" not in tw:
                    errors.append(f"policy '{pol.get('name', i)}' has malformed time_window")
                else:
                    try:
                        _parse_hhmm(tw["start"])
                        _parse_hhmm(tw["end"])
                    except (ValueError, AttributeError, TypeError):
                        errors.append(f"policy '{pol.get('name', i)}' time_window must use HH:MM")
        return errors

    def list_policies(self) -> List[dict]:
        return list(self._policies)

    def evaluate(
        self, agent: str, credential: str, now: Optional[datetime.time] = None
    ) -> Decision:
        if now is None:
            now = datetime.datetime.now().time()

        for pol in self._policies:
            if not self._matches(pol, agent, credential, now):
                continue
            return Decision(
                policy_name=pol["name"],
                auto_approve=bool(pol.get("auto_approve", False)),
                escalate=bool(pol.get("escalate", not pol.get("auto_approve", False))),
            )

        # No policy matched: deny + escalate (defensive default).
        return Decision(policy_name="implicit-deny", auto_approve=False, escalate=True)

    @staticmethod
    def _matches(pol: dict, agent: str, credential: str, now: datetime.time) -> bool:
        if pol["agent"] not in ("*", agent):
            return False
        if pol["credential"] not in ("*", credential):
            return False
        tw = pol.get("time_window")
        if tw is not None:
            if not _in_window(now, _parse_hhmm(tw["start"]), _parse_hhmm(tw["end"])):
                return False
        return True
