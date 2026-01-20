import time

from localpass.vault.models import Vault, VaultEntry, VaultMetadata


def test_add_entry_updates_metadata() -> None:
    vault = Vault(metadata=VaultMetadata())
    entry = VaultEntry.create("github.com", "lukasz", "secret")

    original_updated_at = vault.metadata.updated_at
    time.sleep(0.001)
    vault.add_entry(entry)

    assert len(vault.entries) == 1
    assert vault.metadata.updated_at > original_updated_at


def test_vault_entry_create_defaults() -> None:
    entry1 = VaultEntry.create("service1", "user1", "pass1")
    entry2 = VaultEntry.create("service2", "user2", "pass2")

    # id is empty, to be set by service
    assert entry1.id == ""
    assert entry2.id == ""

    # notes defaults to None
    assert entry1.notes is None
    assert entry2.notes is None

    # tags defaults to empty list, and not shared
    assert entry1.tags == []
    assert entry2.tags == []
    assert entry1.tags is not entry2.tags  # different instances

    # timestamps
    assert entry1.created_at <= entry1.updated_at
    assert entry2.created_at <= entry2.updated_at
