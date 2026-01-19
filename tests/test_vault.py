import pytest
from localpass.vault.models import EntryNotFoundError, Vault, VaultEntry, VaultMetadata


def test_add_entry() -> None:
    vault = Vault(metadata=VaultMetadata())
    entry = VaultEntry.create("gmail", "lukasz", "secret123")
    vault.add_entry(entry)

    assert len(vault.entries) == 1
    assert vault.entries[0].service == "gmail"
    assert vault.entries[0].username == "lukasz"
    assert vault.entries[0].password == "secret123"


def test_remove_entry_by_id_success() -> None:
    vault = Vault(metadata=VaultMetadata())
    entry = VaultEntry.create("gmail", "lukasz", "secret123")
    vault.add_entry(entry)
    entry_id = entry.id

    vault.remove_entry_by_id(entry_id)

    assert len(vault.entries) == 0
    assert vault.metadata.updated_at is not None


def test_remove_entry_by_id_not_found() -> None:
    vault = Vault(metadata=VaultMetadata())

    with pytest.raises(EntryNotFoundError, match="Entry with ID 'nonexistent' not found"):
        vault.remove_entry_by_id("nonexistent")


def test_remove_entry_service() -> None:
    vault = Vault(metadata=VaultMetadata())
    entry1 = VaultEntry.create("gmail", "lukasz", "secret123")
    entry2 = VaultEntry.create("gmail", "other", "password")
    entry3 = VaultEntry.create("github", "lukasz", "token")
    vault.add_entry(entry1)
    vault.add_entry(entry2)
    vault.add_entry(entry3)

    vault.remove_entry("gmail")

    assert len(vault.entries) == 1
    assert vault.entries[0].service == "github"
