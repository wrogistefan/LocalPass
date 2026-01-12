from .models import Vault, VaultEntry, VaultMetadata
from .repository import VaultRepository


class VaultService:
    def __init__(self, repo: VaultRepository):
        self.repo = repo

    def create_vault(self, path: str) -> Vault:
        vault = Vault(metadata=VaultMetadata())
        self.repo.save(path, vault)
        return vault

    def load_vault(self, path: str) -> Vault:
        return self.repo.load(path)

    def add_entry(
        self, vault: Vault, service: str, username: str, password: str, notes=None
    ):
        entry = VaultEntry.create(service, username, password, notes)
        vault.add_entry(entry)
        return entry
