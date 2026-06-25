import json
import pytest
from broker import state


def test_read_mode_initializes_to_auto_when_missing(tmp_path):
    path = str(tmp_path / "mode.json")
    assert state.read_mode(path) == "auto"
    # File now exists with valid shape.
    data = json.loads((tmp_path / "mode.json").read_text())
    assert data["mode"] == "auto"
    assert "updated_at" in data
    assert "updated_by" in data


def test_write_then_read_round_trip(tmp_path):
    path = str(tmp_path / "mode.json")
    state.write_mode(path, "manual", updated_by="cli")
    assert state.read_mode(path) == "manual"


def test_write_rejects_invalid_mode(tmp_path):
    path = str(tmp_path / "mode.json")
    with pytest.raises(ValueError):
        state.write_mode(path, "banana")


def test_toggle_flips_mode(tmp_path):
    path = str(tmp_path / "mode.json")
    assert state.read_mode(path) == "auto"
    assert state.toggle_mode(path) == "manual"
    assert state.read_mode(path) == "manual"
    assert state.toggle_mode(path) == "auto"
    assert state.read_mode(path) == "auto"
