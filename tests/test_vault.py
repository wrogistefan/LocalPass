import pytest

from localpass.vault.models import EntryNotFoundError, Vault, VaultEntry, VaultMetadata
from localpass.vault.service import VaultService
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


def test_vault_from_dict_missing_next_id_computes_from_entries() -> None:
    """Test that missing next_id is computed from entries."""
    data = {
        "metadata": {
            "version": 1,
            "created_at": "2023-01-01T00:00:00Z",
            "updated_at": "2023-01-01T00:00:00Z",
        },
        "entries": [
            {
                "id": "1",
                "service": "test1",
                "username": "user1",
                "password": "pass1",
                "notes": None,
                "tags": [],
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z",
            },
            {
                "id": "3",
                "service": "test3",
                "username": "user3",
                "password": "pass3",
                "notes": None,
                "tags": [],
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z",
            },
        ],
    }
    vault = vault_from_dict(data)
    # Should compute next_id as max(numeric IDs) + 1 = 4
    assert vault.next_id == 4


def test_vault_from_dict_invalid_next_id_falls_back_to_computed() -> None:
    """Test that invalid next_id falls back to computed value."""
    data = {
        "metadata": {
            "version": 1,
            "created_at": "2023-01-01T00:00:00Z",
            "updated_at": "2023-01-01T00:00:00Z",
        },
        "entries": [
            {
                "id": "5",
                "service": "test",
                "username": "user",
                "password": "pass",
                "notes": None,
                "tags": [],
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z",
            },
        ],
        "next_id": "not-a-number",
    }
    vault = vault_from_dict(data)
    # Should fall back to computed value: max(5) + 1 = 6
    assert vault.next_id == 6


def test_vault_from_dict_negative_next_id_normalized() -> None:
    """Test that negative next_id is normalized to minimum."""
    data = {
        "metadata": {
            "version": 1,
            "created_at": "2023-01-01T00:00:00Z",
            "updated_at": "2023-01-01T00:00:00Z",
        },
        "entries": [
            {
                "id": "2",
                "service": "test",
                "username": "user",
                "password": "pass",
                "notes": None,
                "tags": [],
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z",
            },
        ],
        "next_id": -5,
    }
    vault = vault_from_dict(data)
    # Should normalize to computed value: max(2) + 1 = 3
    assert vault.next_id >= 1


def test_compute_next_id_with_only_non_numeric_ids() -> None:
    """Test _compute_next_id_from_entries with only non-numeric IDs."""
    entries = [
        VaultEntry(id="alpha", service="service1", username="user1", password="pass1"),
        VaultEntry(id="beta", service="service2", username="user2", password="pass2"),
    ]

    from localpass.vault.vault_serialization import _compute_next_id_from_entries

    next_id = _compute_next_id_from_entries(entries)

    # Should default to 1 when no numeric IDs exist
    assert next_id == 1


def test_compute_next_id_with_mixed_ids() -> None:
    """Test _compute_next_id_from_entries with mixed numeric/non-numeric IDs."""
    entries = [
        VaultEntry(id="1", service="service1", username="user1", password="pass1"),
        VaultEntry(id="alpha", service="service2", username="user2", password="pass2"),
        VaultEntry(id="5", service="service3", username="user3", password="pass3"),
    ]

    from localpass.vault.vault_serialization import _compute_next_id_from_entries

    next_id = _compute_next_id_from_entries(entries)

    # Should find max numeric ID (5) and return 6
    assert next_id == 6


def test_compute_next_id_with_empty_entries() -> None:
    """Test _compute_next_id_from_entries with no entries."""
    from localpass.vault.vault_serialization import _compute_next_id_from_entries

    next_id = _compute_next_id_from_entries([])

    # Should default to 1
    assert next_id == 1


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


def test_edit_entry_updates_timestamps() -> None:
    """Test that editing an entry updates both entry and vault metadata timestamps."""
    vault = Vault(metadata=VaultMetadata())
    service = VaultService(None)  # type: ignore

    # Add an entry
    entry = service.add_entry(vault, "test-service", "test-user", "test-pass")
    original_entry_created_at = entry.created_at
    original_entry_updated_at = entry.updated_at
    original_vault_updated_at = vault.metadata.updated_at

    # Wait a bit to ensure timestamp difference
    import time

    time.sleep(0.01)

    # Edit the entry
    edited_entry = service.edit_entry(vault, entry.id, username="new-user")

    # Check that timestamps were updated correctly
    assert edited_entry.updated_at > original_entry_updated_at
    assert vault.metadata.updated_at > original_vault_updated_at
    # created_at should remain unchanged when editing an entry
    assert edited_entry.created_at == original_entry_created_at
    assert edited_entry.username == "new-user"


def test_edit_entry_with_notes() -> None:
    """Test that editing an entry with notes parameter updates the notes."""
    vault = Vault(metadata=VaultMetadata())
    service = VaultService(None)  # type: ignore

    # Add an entry
    entry = service.add_entry(
        vault, "test-service", "test-user", "test-pass", notes="old notes"
    )

    # Edit the entry with new notes
    edited_entry = service.edit_entry(vault, entry.id, notes="new notes")

    assert edited_entry.notes == "new notes"


def test_edit_entry_not_found() -> None:
    """Test that editing a non-existent entry raises EntryNotFoundError."""
    vault = Vault(metadata=VaultMetadata())
    service = VaultService(None)  # type: ignore

    with pytest.raises(
        EntryNotFoundError, match="Entry with ID 'nonexistent' not found"
    ):
        service.edit_entry(vault, "nonexistent")


def test_add_entry_assigns_sequential_ids() -> None:
    """Test that VaultService.add_entry assigns sequential IDs correctly."""
    vault = Vault(metadata=VaultMetadata(), next_id=1)
    service = VaultService(None)  # type: ignore

    # First entry: expect id "1" and next_id updated to 2
    entry1 = service.add_entry(vault, "service1", "user1", "pass1")
    assert entry1.id == "1"
    assert vault.next_id == 2

    # Second entry: expect id "2" and next_id updated to 3
    entry2 = service.add_entry(vault, "service2", "user2", "pass2")
    assert entry2.id == "2"
    assert vault.next_id == 3


def test_add_entry_custom_numeric_id_updates_next_id() -> None:
    """Custom numeric entry_id should update vault.next_id appropriately."""
    vault = Vault(metadata=VaultMetadata(), next_id=1)
    service = VaultService(None)  # type: ignore

    entry = service.add_entry(
        vault,
        "service",
        "user",
        "pass",
        entry_id="5",
    )

    assert entry.id == "5"
    # next_id should be updated past the custom numeric ID
    assert vault.next_id == 6


def test_add_entry_custom_non_numeric_id_leaves_next_id_unchanged() -> None:
    """Non-numeric entry_id should leave vault.next_id unchanged."""
    vault = Vault(metadata=VaultMetadata(), next_id=1)
    service = VaultService(None)  # type: ignore

    entry = service.add_entry(
        vault,
        "service",
        "user",
        "pass",
        entry_id="foo",
    )

    assert entry.id == "foo"
    # next_id should not be changed for non-numeric IDs
    assert vault.next_id == 1


def test_add_entry_duplicate_id_raises_value_error() -> None:
    """Duplicate entry_id at the service level should raise ValueError."""
    vault = Vault(metadata=VaultMetadata(), next_id=1)
    service = VaultService(None)  # type: ignore

    # First entry with a specific ID
    first = service.add_entry(
        vault,
        "service1",
        "user1",
        "pass1",
        entry_id="1",
    )
    assert first.id == "1"

    # Second entry with the same ID should raise ValueError
    with pytest.raises(ValueError):
        service.add_entry(
            vault,
            "service2",
            "user2",
            "pass2",
            entry_id="1",
        )
