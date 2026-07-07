from __future__ import annotations

from dataclasses import dataclass

from broker.encrypted_store import EncryptedStore


@dataclass(frozen=True)
class SshResource:
    name: str
    host: str
    port: int
    principal: str
    force_command: str | None
    created_at: str


class SshResourceStore(EncryptedStore):
    """Registered SSH server resources. Nothing in a resource is secret
    (the CA key lives in SshCaStore) — subclassing EncryptedStore buys the
    0600 perms, atomic writes, and per-access disk re-read, not encryption."""

    _SECTION = "ssh_resources"

    def store(self, resource: SshResource) -> None:
        self._entries()[resource.name] = {
            "host": resource.host,
            "port": resource.port,
            "principal": resource.principal,
            "force_command": resource.force_command,
            "created_at": resource.created_at,
        }
        self._write(self._data)

    def get(self, name: str) -> SshResource:
        entries = self._entries()
        if name not in entries:
            raise KeyError(name)
        rec = entries[name]
        return SshResource(
            name=name,
            host=rec["host"],
            port=rec["port"],
            principal=rec["principal"],
            force_command=rec["force_command"],
            created_at=rec["created_at"],
        )

    def delete(self, name: str) -> None:
        entries = self._entries()
        if name not in entries:
            raise KeyError(name)
        del entries[name]
        self._write(self._data)

    def list_names(self) -> list[str]:
        return sorted(self._entries().keys())

    def list_metadata(self) -> list[dict]:
        return [
            {"name": name, **rec}
            for name, rec in sorted(self._entries().items())
        ]
