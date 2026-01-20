from datetime import datetime, timezone
from typing import Optional

from .models import EntryNotFoundError, Vault, VaultEntry, VaultMetadata
from .repository import VaultRepository


class VaultService:
    def __init__(self, repo: VaultRepository):
        self.repo = repo

    def create_vault(self, path: str, master_password: str) -> Vault:
        vault = Vault(metadata=VaultMetadata())
        self.repo.save(path, vault, master_password)
        return vault

    def load_vault(self, path: str, master_password: str) -> Vault:
        return self.repo.load(path, master_password)

    def add_entry(
        self,
        vault: Vault,
        service: str,
        username: str,
        password: str,
        notes: Optional[str] = None,
        entry_id: Optional[str] = None,
    ) -> VaultEntry:
        if entry_id and vault.get_entry_by_id(entry_id) is not None:
            raise ValueError(f"Entry with ID '{entry_id}' already exists.")
        entry = VaultEntry.create(service, username, password, notes)
        if entry_id:
            entry.id = entry_id
            # Adjust next_id to prevent collisions with custom numeric IDs
            try:
                numeric_id = int(entry_id)
                if numeric_id >= vault.next_id:
                    vault.next_id = numeric_id + 1
            except ValueError:
                pass  # Non-numeric IDs don't affect next_id
        else:
            entry.id = str(vault.next_id)
            vault.next_id += 1
        vault.add_entry(entry)
        return entry

    def edit_entry(
        self,
        vault: Vault,
        entry_id: str,
        service: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> VaultEntry:
        entry = vault.get_entry_by_id(entry_id)
        if entry is None:
            raise EntryNotFoundError(f"Entry with ID '{entry_id}' not found.")
        if service is not None:
            entry.service = service
        if username is not None:
            entry.username = username
        if password is not None:
            entry.password = password
        if notes is not None:
            entry.notes = notes
        entry.updated_at = datetime.now(timezone.utc)
        vault.metadata.updated_at = datetime.now(timezone.utc)
        return entry
