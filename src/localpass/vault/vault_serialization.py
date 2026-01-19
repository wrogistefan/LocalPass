from datetime import datetime, timezone
from typing import Any, Dict

from .models import Vault, VaultEntry, VaultMetadata


def _parse_iso8601(path: str, field_desc: str, value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(
            f"Invalid ISO8601 timestamp for {field_desc} in vault {path}: {value}"
        ) from exc
    # Normalize to UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    elif dt.tzinfo != timezone.utc:
        raise ValueError(
            f"Timestamp for {field_desc} in vault {path} must be in UTC timezone: {value}"
        )
    return dt


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
        created_at = _parse_iso8601(
            path, "metadata created_at", metadata_dict["created_at"]
        )
        updated_at = _parse_iso8601(
            path, "metadata updated_at", metadata_dict["updated_at"]
        )
        metadata = VaultMetadata(
            version=metadata_dict["version"],
            created_at=created_at,
            updated_at=updated_at,
        )
        entries = []
        for e in data["entries"]:
            entry_created_at = _parse_iso8601(
                path,
                f"created_at in entry {e.get('id', 'unknown')}",
                e["created_at"],
            )
            entry_updated_at = _parse_iso8601(
                path,
                f"updated_at in entry {e.get('id', 'unknown')}",
                e["updated_at"],
            )
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
