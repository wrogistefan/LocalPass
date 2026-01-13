import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


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
            id=str(uuid.uuid4()),
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

    def remove_entry_by_id(self, entry_id: str) -> bool:
        for i, entry in enumerate(self.entries):
            if entry.id == entry_id:
                del self.entries[i]
                self.metadata.updated_at = datetime.now(timezone.utc)
                return True
        return False
