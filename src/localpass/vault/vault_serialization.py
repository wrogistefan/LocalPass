from datetime import datetime
from typing import Any, Dict

from .models import Vault, VaultEntry, VaultMetadata


def vault_to_dict(vault: Vault) -> Dict[str, Any]:
    """Convert a Vault object to a dictionary for JSON serialization."""
    return {
        "metadata": {
            "version": vault.metadata.version,
            "created_at": vault.metadata.created_at.isoformat(),
            "updated_at": vault.metadata.updated_at.isoformat(),
        },
        "entries": [
            {
                "id": e.id,
                "service": e.service,
                "username": e.username,
                "password": e.password,
                "notes": e.notes,
                "tags": e.tags,
                "created_at": e.created_at.isoformat(),
                "updated_at": e.updated_at.isoformat(),
            }
            for e in vault.entries
        ],
    }


def vault_from_dict(data: Dict[str, Any], path: str = "<in-memory>") -> Vault:
    """Convert a dictionary to a Vault object.

    Args:
        data: Dictionary containing vault data
        path: Path to the vault file (for error messages)

    Returns:
        Vault object

    Raises:
        ValueError: If required fields are missing or data format is invalid
    """
    try:
        metadata_dict = data["metadata"]
        try:
            created_at = datetime.fromisoformat(metadata_dict["created_at"])
        except ValueError:
            raise ValueError(f"Invalid ISO8601 timestamp for metadata created_at in vault {path}: {metadata_dict['created_at']}")
        try:
            updated_at = datetime.fromisoformat(metadata_dict["updated_at"])
        except ValueError:
            raise ValueError(f"Invalid ISO8601 timestamp for metadata updated_at in vault {path}: {metadata_dict['updated_at']}")
        metadata = VaultMetadata(
            version=metadata_dict["version"],
            created_at=created_at,
            updated_at=updated_at,
        )
        entries = []
        for e in data["entries"]:
            try:
                entry_created_at = datetime.fromisoformat(e["created_at"])
            except ValueError:
                raise ValueError(f"Invalid ISO8601 timestamp for created_at in entry {e.get('id', 'unknown')} in vault {path}: {e['created_at']}")
            try:
                entry_updated_at = datetime.fromisoformat(e["updated_at"])
            except ValueError:
                raise ValueError(f"Invalid ISO8601 timestamp for updated_at in entry {e.get('id', 'unknown')} in vault {path}: {e['updated_at']}")
            entries.append(
                VaultEntry(
                    id=e["id"],
                    service=e["service"],
                    username=e["username"],
                    password=e["password"],
                    notes=e.get("notes"),
                    tags=e.get("tags", []),
                    created_at=entry_created_at,
                    updated_at=entry_updated_at,
                )
            )
    except KeyError as exc:
        raise ValueError(f"Missing required field in vault data: {exc}")
    except ValueError as exc:
        raise ValueError(f"Invalid data format in vault file {path}: {exc}")

    return Vault(metadata=metadata, entries=entries)
