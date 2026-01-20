from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


class EntryNotFoundError(Exception):
    """Raised when a vault entry with the given ID does not exist."""

    pass


@dataclass
class VaultEntry:
    id: str
    service: str
    username: str
    password: str
    notes: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @staticmethod
    def create(
        service: str, username: str, password: str, notes: Optional[str] = None
    ) -> "VaultEntry":
        return VaultEntry(
            id="",  # Will be set by service
            service=service,
            username=username,
            password=password,
            notes=notes,
        )


@dataclass
class VaultMetadata:
    version: int = 1
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Vault:
    metadata: VaultMetadata
    entries: List[VaultEntry] = field(default_factory=list)
    next_id: int = 1

    def add_entry(self, entry: VaultEntry) -> None:
        self.entries.append(entry)
        self.metadata.updated_at = datetime.now(timezone.utc)

    def list_entries(self) -> List[VaultEntry]:
        return self.entries[:]

    def remove_entry(self, service: str) -> None:
        self.entries = [e for e in self.entries if e.service != service]
        self.metadata.updated_at = datetime.now(timezone.utc)

    def get_entry_by_id(self, entry_id: str) -> Optional[VaultEntry]:
        for entry in self.entries:
            if entry.id == entry_id:
                return entry
        return None

    def remove_entry_by_id(self, entry_id: str) -> None:
        for i, entry in enumerate(self.entries):
            if entry.id == entry_id:
                del self.entries[i]
                self.metadata.updated_at = datetime.now(timezone.utc)
                return
        raise EntryNotFoundError(f"Entry with ID '{entry_id}' not found.")
