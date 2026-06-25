from __future__ import annotations

import datetime
import json
import os

_VALID_MODES = {"auto", "manual"}


def _now() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


def write_mode(path: str, mode: str, updated_by: str = "cli") -> None:
    if mode not in _VALID_MODES:
        raise ValueError(f"mode must be one of {_VALID_MODES}, got {mode!r}")
    payload = {"mode": mode, "updated_at": _now(), "updated_by": updated_by}
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    os.replace(tmp, path)


def read_mode(path: str) -> str:
    if not os.path.exists(path):
        write_mode(path, "auto", updated_by="init")
        return "auto"
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)["mode"]


def toggle_mode(path: str, updated_by: str = "cli") -> str:
    new_mode = "manual" if read_mode(path) == "auto" else "auto"
    write_mode(path, new_mode, updated_by=updated_by)
    return new_mode
