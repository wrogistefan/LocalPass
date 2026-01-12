import json
from pathlib import Path
from .models import Vault, VaultMetadata, VaultEntry


class VaultRepository:
    def load(self, path: str) -> Vault:
        data = json.loads(Path(path).read_text())

        metadata = VaultMetadata(**data["metadata"])
        entries = [VaultEntry(**e) for e in data["entries"]]

        return Vault(metadata=metadata, entries=entries)

    def save(self, path: str, vault: Vault) -> None:
        data = {
            "metadata": vars(vault.metadata),
            "entries": [vars(e) for e in vault.entries],
        }
        Path(path).write_text(json.dumps(data, indent=2))
