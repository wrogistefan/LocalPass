import pytest

from localpass.vault.models import EntryNotFoundError, Vault, VaultEntry, VaultMetadata
from localpass.vault.vault_serialization import vault_from_dict


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

    with pytest.raises(
        EntryNotFoundError, match="Entry with ID 'nonexistent' not found"
    ):
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


def test_vault_from_dict_missing_tags() -> None:
    """Test that missing tags in entry defaults to empty list."""
    data = {
        "metadata": {
            "version": 1,
            "created_at": "2023-01-01T00:00:00",
            "updated_at": "2023-01-01T00:00:00",
        },
        "entries": [
            {
                "id": "123",
                "service": "test",
                "username": "user",
                "password": "pass",
                "notes": None,
                # "tags" is missing
                "created_at": "2023-01-01T00:00:00",
                "updated_at": "2023-01-01T00:00:00",
            }
        ],
    }
    vault = vault_from_dict(data)
    assert len(vault.entries) == 1
    assert vault.entries[0].tags == []


def test_vault_from_dict_missing_notes() -> None:
    """Test that missing notes in entry defaults to None."""
    data = {
        "metadata": {
            "version": 1,
            "created_at": "2023-01-01T00:00:00",
            "updated_at": "2023-01-01T00:00:00",
        },
        "entries": [
            {
                "id": "123",
                "service": "test",
                "username": "user",
                "password": "pass",
                "tags": ["tag1"],
                # "notes" is missing
                "created_at": "2023-01-01T00:00:00",
                "updated_at": "2023-01-01T00:00:00",
            }
        ],
    }
    vault = vault_from_dict(data)
    assert len(vault.entries) == 1
    assert vault.entries[0].notes is None


def test_vault_from_dict_invalid_timestamp() -> None:
    """Test that invalid timestamp raises ValueError."""
    data = {
        "metadata": {
            "version": 1,
            "created_at": "invalid-date",
            "updated_at": "2023-01-01T00:00:00",
        },
        "entries": [],
    }
    with pytest.raises(ValueError, match="Invalid data format"):
        vault_from_dict(data)


def test_vault_operations_edge_cases() -> None:
    """Test edge cases for vault operations."""
    vault = Vault(metadata=VaultMetadata())

    # Add entry with empty tags
    entry = VaultEntry.create("service", "user", "pass")
    entry.tags = []
    vault.add_entry(entry)
    assert len(vault.entries) == 1

    # Remove non-existent service
    vault.remove_entry("nonexistent")  # Should not raise
    assert len(vault.entries) == 1

    # Remove entry with multiple matches
    entry2 = VaultEntry.create("service", "user2", "pass2")
    vault.add_entry(entry2)
    vault.remove_entry("service")  # Should remove all with service
    assert len(vault.entries) == 0
