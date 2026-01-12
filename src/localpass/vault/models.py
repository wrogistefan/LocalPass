import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class VaultEntry:
    id: str
    service: str
    username: str
    password: str
    notes: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    @staticmethod
    def create(service: str, username: str, password: str, notes: Optional[str] = None):
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
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Vault:
    metadata: VaultMetadata
    entries: List[VaultEntry] = field(default_factory=list)

    def add_entry(self, entry: VaultEntry):
        self.entries.append(entry)
        self.metadata.updated_at = datetime.utcnow()
