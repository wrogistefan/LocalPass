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
    with pytest.raises(ValueError, match="Invalid ISO8601 timestamp"):
        vault_from_dict(data)


def test_vault_operations_with_empty_tags() -> None:
    """Vault handles entries with empty tags without errors."""
    vault = Vault(metadata=VaultMetadata())

    # Initially no entries
    assert len(vault.entries) == 0

    # Add an entry with empty tags
    entry = VaultEntry.create("email", "user@example.com", "secret")
    entry.tags = []
    vault.add_entry(entry)

    assert len(vault.entries) == 1
    entry = vault.entries[0]
    # Explicitly check we keep empty tags as-is
    assert entry.tags == []


def test_remove_entry_nonexistent_service_does_not_change_entries() -> None:
    """Removing a non-existent service must not change existing entries."""
    vault = Vault(metadata=VaultMetadata())

    vault.add_entry(VaultEntry.create("service-a", "alice", "pw-a"))
    vault.add_entry(VaultEntry.create("service-b", "bob", "pw-b"))

    # Sanity check: we start with two entries
    assert len(vault.entries) == 2

    # Removing a service that does not exist should not change the vault
    vault.remove_entry("non-existent-service")

    # Length and contents should be unchanged
    assert len(vault.entries) == 2
    assert {e.service for e in vault.entries} == {"service-a", "service-b"}


def test_remove_entry_removes_all_matching_services() -> None:
    """Removing a service removes all entries for that service."""
    vault = Vault(metadata=VaultMetadata())

    vault.add_entry(VaultEntry.create("service-a", "alice", "pw-a"))
    vault.add_entry(VaultEntry.create("service-a", "alice-alt", "pw-a2"))
    vault.add_entry(VaultEntry.create("service-b", "bob", "pw-b"))

    # We start with three entries, two for service-a
    assert len(vault.entries) == 3
    assert [e.service for e in vault.entries].count("service-a") == 2
    assert [e.service for e in vault.entries].count("service-b") == 1

    # When we remove service-a, all its entries should be removed
    vault.remove_entry("service-a")

    # Only the service-b entry should remain
    assert len(vault.entries) == 1
    assert vault.entries[0].service == "service-b"


def test_vault_from_dict_tags_not_list() -> None:
    """Test that tags not being a list raises ValueError."""
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
                "tags": "not_a_list",  # Invalid: should be list
                "notes": "notes",
                "created_at": "2023-01-01T00:00:00",
                "updated_at": "2023-01-01T00:00:00",
            }
        ],
    }

    with pytest.raises(ValueError, match="Tags must be a list"):
        vault_from_dict(data, "test.json")


def test_vault_from_dict_non_utc_timezone() -> None:
    """Test that non-UTC timezone in metadata raises ValueError."""
    data = {
        "metadata": {
            "version": 1,
            "created_at": "2023-01-01T00:00:00+01:00",  # Non-UTC
            "updated_at": "2023-01-01T00:00:00",
        },
        "entries": [],
    }

    with pytest.raises(ValueError, match="must be in UTC timezone"):
        vault_from_dict(data, "test.json")
