import base64
import json
import os
from pathlib import Path
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidTag

from .crypto import decrypt, derive_key, encrypt
from .models import Vault
from .vault_serialization import vault_to_dict, vault_from_dict


@runtime_checkable
class VaultRepository(Protocol):
    """Abstract interface for vault repositories."""
    
    def load(self, path: str | Path, master_password: str | None = None) -> Vault:
        """Load a vault from the specified path.
        
        Args:
            path: Path to the vault file
            master_password: Optional master password for encrypted vaults
            
        Returns:
            Vault object
            
        Raises:
            ValueError: If the vault cannot be loaded
        """
        ...
    
    def save(self, path: str | Path, vault: Vault, master_password: str | None = None) -> None:
        """Save a vault to the specified path.
        
        Args:
            path: Path to save the vault file
            vault: Vault object to save
            master_password: Optional master password for encrypted vaults
            
        Raises:
            ValueError: If the vault cannot be saved
        """
        ...


class PlaintextVaultRepository:
    def load(self, path: str | Path, master_password: str | None = None) -> Vault:
        try:
            data = json.loads(Path(path).read_text())
        except FileNotFoundError:
            raise ValueError(f"Vault file not found: {path}")
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in vault file {path}: {exc}")

        return vault_from_dict(data, str(path))

    def save(self, path: str | Path, vault: Vault, master_password: str | None = None) -> None:
        data = vault_to_dict(vault)
        Path(path).write_text(json.dumps(data, indent=2))


class EncryptedVaultRepository:
    def save(self, path: str | Path, vault: Vault, master_password: str | None = None) -> None:
        if master_password is None:
            raise ValueError("master_password is required for encrypted vaults")
        
        plaintext = json.dumps(vault_to_dict(vault)).encode("utf-8")
        salt = os.urandom(16)
        key = derive_key(master_password, salt)
        nonce, ciphertext = encrypt(plaintext, key)
        encrypted_data = {
            "version": 1,
            "kdf": "argon2id",
            "salt": base64.b64encode(salt).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        }
        Path(path).write_text(json.dumps(encrypted_data, indent=2))

    def load(self, path: str | Path, master_password: str | None = None) -> Vault:
        if master_password is None:
            raise ValueError("master_password is required for encrypted vaults")
            
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
        except Exception as exc:
            raise ValueError("Invalid password or corrupted vault")

        key = derive_key(master_password, salt)
        try:
            plaintext = decrypt(ciphertext, key, nonce)
        except InvalidTag:
            raise ValueError("Invalid password or corrupted vault")
        except Exception as exc:
            raise ValueError(f"Decryption failed: {exc}")

        try:
            obj = json.loads(plaintext.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in decrypted vault data: {exc}")

        return vault_from_dict(obj, str(path))
