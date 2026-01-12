import base64
import json
import os
from datetime import datetime
from pathlib import Path

from .crypto import decrypt, derive_key, encrypt
from .models import Vault, VaultEntry, VaultMetadata


class PlaintextVaultRepository:
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


class EncryptedVaultRepository:
    def save(self, path: str, vault: Vault, master_password: str) -> None:
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
        plaintext = json.dumps(data).encode('utf-8')
        salt = os.urandom(16)
        key = derive_key(master_password, salt)
        nonce, ciphertext = encrypt(plaintext, key)
        encrypted_data = {
            "version": 1,
            "kdf": "argon2id",
            "salt": base64.b64encode(salt).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }
        Path(path).write_text(json.dumps(encrypted_data, indent=2))

    def load(self, path: str, master_password: str) -> Vault:
        try:
            data = json.loads(Path(path).read_text())
        except FileNotFoundError:
            raise ValueError(f"Vault file not found: {path}")
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in vault file {path}: {exc}")

        try:
            salt = base64.b64decode(data["salt"])
            nonce = base64.b64decode(data["nonce"])
            ciphertext = base64.b64decode(data["ciphertext"])
        except KeyError as exc:
            raise ValueError(f"Missing required field in encrypted vault data: {exc}")

        key = derive_key(master_password, salt)
        try:
            plaintext = decrypt(ciphertext, key, nonce)
        except Exception as exc:
            raise ValueError(f"Decryption failed: {exc}")

        try:
            obj = json.loads(plaintext.decode('utf-8'))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in decrypted vault data: {exc}")

        try:
            metadata_dict = obj["metadata"]
            metadata = VaultMetadata(
                version=metadata_dict["version"],
                created_at=datetime.fromisoformat(metadata_dict["created_at"]),
                updated_at=datetime.fromisoformat(metadata_dict["updated_at"]),
            )
            entries = []
            for e in obj["entries"]:
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
