import base64
import json
import os
import warnings
from pathlib import Path
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidTag

from .crypto import decrypt, derive_key, encrypt
from .models import Vault
from .vault_serialization import vault_from_dict, vault_to_dict


class IncorrectPasswordError(ValueError):
    """Raised when the master password is incorrect."""

    pass


class CorruptedVaultError(ValueError):
    """Raised when the vault file is corrupted or unreadable."""

    pass


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

    def save(
        self, path: str | Path, vault: Vault, master_password: str | None = None
    ) -> None:
        """Save a vault to the specified path.

        Args:
            path: Path to save the vault file
            vault: Vault object to save
            master_password: Optional master password for encrypted vaults

        Raises:
            ValueError: If the vault cannot be saved
        """
        ...


class PlaintextVaultRepository(VaultRepository):
    """WARNING: This repository stores vault data in plaintext and is UNSAFE for production use.

    It is intended ONLY for testing, debugging, or isolated environments where security is not a concern.
    Do not use this in any environment where data confidentiality is required.
    """

    def __init__(self) -> None:
        warnings.warn(
            "PlaintextVaultRepository stores vault data in plaintext and must not be used in production environments.",
            UserWarning,
            stacklevel=2,
        )

    def load(self, path: str | Path, master_password: str | None = None) -> Vault:
        try:
            data = json.loads(Path(path).read_text())
        except FileNotFoundError:
            raise ValueError(f"Vault file not found: {path}")
        except json.JSONDecodeError as exc:
            raise CorruptedVaultError(f"Invalid JSON in vault file {path}: {exc}")

        return vault_from_dict(data, str(path))

    def save(
        self, path: str | Path, vault: Vault, master_password: str | None = None
    ) -> None:
        data = vault_to_dict(vault)
        Path(path).write_text(json.dumps(data, indent=2))


class EncryptedVaultRepository:
    def save(
        self, path: str | Path, vault: Vault, master_password: str | None = None
    ) -> None:
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
            raise CorruptedVaultError(f"Invalid JSON in vault file {path}: {exc}")

        try:
            salt = base64.b64decode(data["salt"])
            nonce = base64.b64decode(data["nonce"])
            ciphertext = base64.b64decode(data["ciphertext"])
        except KeyError as exc:
            raise CorruptedVaultError(
                f"Missing required field in encrypted vault data: {exc}"
            )
        except Exception:
            raise CorruptedVaultError("Vault file is corrupted or unreadable.")

        key = derive_key(master_password, salt)
        try:
            plaintext = decrypt(ciphertext, key, nonce)
        except InvalidTag as exc:
            # Authentication tag mismatch can indicate either an incorrect password
            # or tampered/corrupted ciphertext. We distinguish based on context:
            # - If the vault file parsed successfully and all required fields are present,
            #   InvalidTag most likely means incorrect password.
            # - If corruption is detected elsewhere, CorruptedVaultError is raised first.
            raise IncorrectPasswordError("Incorrect master password.") from exc
        except (ValueError, TypeError) as exc:
            # ValueError: decryption produced invalid data
            # TypeError: argument type mismatch
            raise CorruptedVaultError(f"Decryption failed: {exc}") from exc
        except Exception as exc:
            raise CorruptedVaultError(
                f"Decryption failed (unexpected error): {exc}"
            ) from exc

        try:
            obj = json.loads(plaintext.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise CorruptedVaultError(f"Invalid JSON in decrypted vault data: {exc}")

        return vault_from_dict(obj, str(path))
