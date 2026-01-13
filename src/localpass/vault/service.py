from typing import Optional

from .models import Vault, VaultEntry, VaultMetadata
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
    ) -> VaultEntry:
        entry = VaultEntry.create(service, username, password, notes)
        vault.add_entry(entry)
        return entry
