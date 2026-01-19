from datetime import datetime

import pytest

from localpass.vault.models import EntryNotFoundError, Vault, VaultEntry, VaultMetadata
from localpass.vault.vault_serialization import vault_from_dict, vault_to_dict


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


def test_vault_serialization_roundtrip() -> None:
    vault = Vault(metadata=VaultMetadata())
    entry = VaultEntry.create("github", "lukasz", "secret")
    vault.add_entry(entry)

    data = vault_to_dict(vault)

    # Basic structure guarantees
    assert set(data.keys()) == {"metadata", "entries"}

    metadata = data["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["version"] == vault.metadata.version
    assert "created_at" in metadata
    assert "updated_at" in metadata

    # ISO8601 timestamp guarantees (parseable as ISO8601)
    for ts_key in ("created_at", "updated_at"):
        ts_value = metadata[ts_key]
        assert isinstance(ts_value, str)
        # Allow a trailing 'Z' by normalizing to a UTC offset
        normalized = ts_value.replace("Z", "+00:00")
        datetime.fromisoformat(normalized)

    entries = data["entries"]
    assert isinstance(entries, list)
    assert len(entries) == 1

    entry_data = entries[0]
    assert entry_data["service"] == "github"
    # Ensure tags field is always present in serialization
    assert "tags" in entry_data
    assert entry_data["tags"] == []

    # Roundtrip guarantees
    loaded = vault_from_dict(data)

    assert loaded.metadata.version == vault.metadata.version
    assert len(loaded.entries) == 1
    assert loaded.entries[0].service == "github"
    assert loaded.entries[0].tags == []


def test_vault_serialization_missing_tags() -> None:
    data = {
        "metadata": {
            "version": 1,
            "created_at": "2023-01-01T00:00:00",
            "updated_at": "2023-01-01T00:00:00",
        },
        "entries": [
            {
                "id": "123",
                "service": "github",
                "username": "lukasz",
                "password": "secret",
                "notes": None,
                # "tags" is missing
                "created_at": "2023-01-01T00:00:00",
                "updated_at": "2023-01-01T00:00:00",
            }
        ],
    }
    vault = vault_from_dict(data)
    assert vault.entries[0].tags == []


def test_vault_serialization_valid_timestamps() -> None:
    data = {
        "metadata": {
            "version": 1,
            "created_at": "2023-01-01T00:00:00",
            "updated_at": "2023-01-01T00:00:00",
        },
        "entries": [
            {
                "id": "123",
                "service": "github",
                "username": "lukasz",
                "password": "secret",
                "notes": None,
                "tags": [],
                "created_at": "2023-01-01T00:00:00",
                "updated_at": "2023-01-01T00:00:00",
            }
        ],
    }
    vault = vault_from_dict(data)
    assert vault.metadata.created_at.isoformat() == "2023-01-01T00:00:00+00:00"
    assert vault.entries[0].created_at.isoformat() == "2023-01-01T00:00:00+00:00"


def test_vault_serialization_invalid_timestamp_metadata() -> None:
    data = {
        "metadata": {
            "version": 1,
            "created_at": "invalid-date",
            "updated_at": "2023-01-01T00:00:00",
        },
        "entries": [],
    }
    with pytest.raises(
        ValueError, match="Invalid ISO8601 timestamp for metadata created_at"
    ):
        vault_from_dict(data)


def test_vault_serialization_invalid_timestamp_metadata_updated_at() -> None:
    data = {
        "metadata": {
            "version": 1,
            "created_at": "2023-01-01T00:00:00",
            "updated_at": "invalid-date",
        },
        "entries": [],
    }
    with pytest.raises(
        ValueError, match="Invalid ISO8601 timestamp for metadata updated_at"
    ):
        vault_from_dict(data)


def test_vault_serialization_invalid_timestamp_entry() -> None:
    data = {
        "metadata": {
            "version": 1,
            "created_at": "2023-01-01T00:00:00",
            "updated_at": "2023-01-01T00:00:00",
        },
        "entries": [
            {
                "id": "123",
                "service": "github",
                "username": "lukasz",
                "password": "secret",
                "notes": None,
                "tags": [],
                "created_at": "invalid-date",
                "updated_at": "2023-01-01T00:00:00",
            }
        ],
    }
    with pytest.raises(
        ValueError, match="Invalid ISO8601 timestamp for created_at in entry 123"
    ):
        vault_from_dict(data)


def test_vault_serialization_invalid_timestamp_entry_updated_at() -> None:
    data = {
        "metadata": {
            "version": 1,
            "created_at": "2023-01-01T00:00:00",
            "updated_at": "2023-01-01T00:00:00",
        },
        "entries": [
            {
                "id": "123",
                "service": "github",
                "username": "lukasz",
                "password": "secret",
                "notes": None,
                "tags": [],
                "created_at": "2023-01-01T00:00:00",
                "updated_at": "invalid-date",
            }
        ],
    }
    with pytest.raises(
        ValueError, match="Invalid ISO8601 timestamp for updated_at in entry 123"
    ):
        vault_from_dict(data)


def test_vault_serialization_invalid_timestamp_entry_unknown_id() -> None:
    data = {
        "metadata": {
            "version": 1,
            "created_at": "2023-01-01T00:00:00",
            "updated_at": "2023-01-01T00:00:00",
        },
        "entries": [
            {
                # intentionally no "id" field to trigger the 'unknown' fallback
                "service": "github",
                "username": "lukasz",
                "password": "secret",
                "notes": None,
                "tags": [],
                "created_at": "invalid-date",
                "updated_at": "2023-01-01T00:00:00",
            }
        ],
    }
    with pytest.raises(
        ValueError, match="Invalid ISO8601 timestamp for created_at in entry unknown"
    ):
        vault_from_dict(data)


def test_vault_serialization_missing_timestamp() -> None:
    data = {
        "metadata": {
            "version": 1,
            "created_at": "2023-01-01T00:00:00",
            "updated_at": "2023-01-01T00:00:00",
        },
        "entries": [
            {
                "id": "123",
                "service": "github",
                "username": "lukasz",
                "password": "secret",
                "notes": None,
                "tags": [],
                # "created_at" is missing
                "updated_at": "2023-01-01T00:00:00",
            }
        ],
    }
    with pytest.raises(ValueError, match="Missing required field"):
        vault_from_dict(data)
