from __future__ import annotations

import os

import pytest

from broker.credential_store import CredentialStore


def test_broker_instance_sees_cli_writes_without_restart(tmp_path):
    """The long-running broker's store must pick up writes made by a separate
    CLI process (simulated here by a second instance over the same file)."""
    path = str(tmp_path / "creds.json")
    broker_side = CredentialStore(path, "pw")
    cli_side = CredentialStore(path, "pw")
    cli_side.store("new-key", "sk-added-later")
    assert broker_side.retrieve("new-key") == "sk-added-later"
    cli_side.delete("new-key")
    assert broker_side.list_names() == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_store_file_is_owner_only(tmp_path):
    path = tmp_path / "creds.json"
    CredentialStore(str(path), "pw").store("k", "v")
    assert (os.stat(path).st_mode & 0o777) == 0o600


def test_password_not_retained_on_instance(tmp_path):
    store = CredentialStore(str(tmp_path / "creds.json"), "hunter2")
    for value in vars(store).values():
        assert value != "hunter2"
