import json
import pytest
from broker import state


def test_read_mode_defaults_to_auto_when_missing_without_writing(tmp_path):
    path = str(tmp_path / "mode.json")
    assert state.read_mode(path) == "auto"
    # A read must not create the file (the mount may be read-only).
    assert not (tmp_path / "mode.json").exists()


def test_read_mode_corrupt_file_fails_closed_to_manual(tmp_path):
    path = tmp_path / "mode.json"
    path.write_text("{not json at all")
    assert state.read_mode(str(path)) == "manual"
    path.write_text(json.dumps({"mode": "banana"}))
    assert state.read_mode(str(path)) == "manual"
    path.write_text(json.dumps({"wrong_key": "auto"}))
    assert state.read_mode(str(path)) == "manual"


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
