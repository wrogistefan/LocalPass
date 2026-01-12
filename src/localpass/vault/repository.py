import json
from datetime import datetime
from pathlib import Path

from .models import Vault, VaultEntry, VaultMetadata


class VaultRepository:
    def load(self, path: str) -> Vault:
        try:
            data = json.loads(Path(path).read_text())
        except FileNotFoundError:
            raise ValueError(f"Vault file not found: {path}")
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in vault file {path}: {exc}")

        try:
            metadata_dict = data["metadata"]
            metadata = VaultMetadata(
                version=metadata_dict["version"],
                created_at=datetime.fromisoformat(metadata_dict["created_at"]),
                updated_at=datetime.fromisoformat(metadata_dict["updated_at"]),
            )
            entries = []
            for e in data["entries"]:
                entries.append(
                    VaultEntry(
                        id=e["id"],
                        service=e["service"],
                        username=e["username"],
                        password=e["password"],
                        notes=e.get("notes"),
                        tags=e["tags"],
                        created_at=datetime.fromisoformat(e["created_at"]),
                        updated_at=datetime.fromisoformat(e["updated_at"]),
                    )
                )
        except KeyError as exc:
            raise ValueError(f"Missing required field in vault data: {exc}")
        except ValueError as exc:
            raise ValueError(f"Invalid data format in vault file {path}: {exc}")

        return Vault(metadata=metadata, entries=entries)

    def save(self, path: str, vault: Vault) -> None:
        data = {
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
        Path(path).write_text(json.dumps(data, indent=2))
