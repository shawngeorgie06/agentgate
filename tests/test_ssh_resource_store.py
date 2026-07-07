from __future__ import annotations

import pytest

from broker.ssh_resource_store import SshResource, SshResourceStore


def _res(name="web-1", force_command=None):
    return SshResource(
        name=name, host="10.0.0.5", port=22, principal="deploy",
        force_command=force_command, created_at="2026-07-05T10:00:00+00:00",
    )


def test_store_get_roundtrip(tmp_path):
    store = SshResourceStore(str(tmp_path / "ssh.json"), "pw")
    store.store(_res(force_command="echo ok"))
    got = store.get("web-1")
    assert got == _res(force_command="echo ok")


def test_get_unknown_raises_keyerror(tmp_path):
    store = SshResourceStore(str(tmp_path / "ssh.json"), "pw")
    with pytest.raises(KeyError):
        store.get("nope")


def test_delete_and_list_names(tmp_path):
    store = SshResourceStore(str(tmp_path / "ssh.json"), "pw")
    store.store(_res("b")); store.store(_res("a"))
    assert store.list_names() == ["a", "b"]
    store.delete("a")
    assert store.list_names() == ["b"]
    with pytest.raises(KeyError):
        store.delete("a")


def test_list_metadata_includes_everything(tmp_path):
    # Nothing in an SshResource is secret; metadata is the full record.
    store = SshResourceStore(str(tmp_path / "ssh.json"), "pw")
    store.store(_res(force_command="echo ok"))
    (meta,) = store.list_metadata()
    assert meta == {
        "name": "web-1", "host": "10.0.0.5", "port": 22, "principal": "deploy",
        "force_command": "echo ok", "created_at": "2026-07-05T10:00:00+00:00",
    }
