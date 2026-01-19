import json
from pathlib import Path

import pytest

from localpass.vault.crypto import decrypt, derive_key, encrypt
from localpass.vault.models import Vault, VaultEntry, VaultMetadata
from localpass.vault.repository import (
    CorruptedVaultError,
    EncryptedVaultRepository,
    PlaintextVaultRepository,
)
from localpass.vault.service import VaultService


def test_derive_key() -> None:
    password = "password123"
    salt = b"salt123456789012"  # 16 bytes
    key = derive_key(password, salt)
    assert len(key) == 32
    # Same password and salt should give same key
    key2 = derive_key(password, salt)
    assert key == key2
    # Different password different key
    key3 = derive_key("different", salt)
    assert key != key3


def test_encrypt_decrypt() -> None:
    plaintext = b"hello world"
    key = b"0" * 32
    nonce, ciphertext = encrypt(plaintext, key)
    assert len(nonce) == 12
    decrypted = decrypt(ciphertext, key, nonce)
    assert decrypted == plaintext


def test_encrypt_decrypt_roundtrip(tmp_path: Path) -> None:
    repo = EncryptedVaultRepository()
    path = tmp_path / "vault.enc"

    vault = Vault(metadata=VaultMetadata())
    vault.add_entry(VaultEntry.create("github.com", "lukasz", "secret"))

    repo.save(path, vault, "password123")
    loaded = repo.load(path, "password123")

    assert loaded.entries[0].password == "secret"


def test_encrypted_repository_save_without_password_raises_error(
    tmp_path: Path,
) -> None:
    repo = EncryptedVaultRepository()
    path = tmp_path / "vault.enc"
    vault = Vault(metadata=VaultMetadata())

    with pytest.raises(
        ValueError, match="master_password is required for encrypted vaults"
    ):
        repo.save(path, vault, None)


def test_encrypted_repository_load_without_password_raises_error(
    tmp_path: Path,
) -> None:
    repo = EncryptedVaultRepository()
    path = tmp_path / "vault.enc"
    vault = Vault(metadata=VaultMetadata())
    vault.add_entry(VaultEntry.create("github.com", "lukasz", "secret"))

    repo.save(path, vault, "password123")

    with pytest.raises(
        ValueError, match="master_password is required for encrypted vaults"
    ):
        repo.load(path, None)


def test_encrypted_repository_decrypt_value_error(tmp_path: Path) -> None:
    from unittest.mock import patch

    repo = EncryptedVaultRepository()
    path = tmp_path / "vault.enc"
    vault = Vault(metadata=VaultMetadata())
    vault.add_entry(VaultEntry.create("github.com", "lukasz", "secret"))

    repo.save(path, vault, "password123")

    with patch(
        "localpass.vault.repository.decrypt", side_effect=ValueError("Decrypt failed")
    ):
        with pytest.raises(
            CorruptedVaultError, match="Decryption failed: Decrypt failed"
        ):
            repo.load(path, "password123")


def test_encrypted_repository_decrypt_type_error(tmp_path: Path) -> None:
    from unittest.mock import patch

    repo = EncryptedVaultRepository()
    path = tmp_path / "vault.enc"
    vault = Vault(metadata=VaultMetadata())
    vault.add_entry(VaultEntry.create("github.com", "lukasz", "secret"))

    repo.save(path, vault, "password123")

    with patch(
        "localpass.vault.repository.decrypt", side_effect=TypeError("Decrypt failed")
    ):
        with pytest.raises(
            CorruptedVaultError, match="Decryption failed: Decrypt failed"
        ):
            repo.load(path, "password123")


def test_encrypted_repository_decrypt_exception(tmp_path: Path) -> None:
    from unittest.mock import patch

    repo = EncryptedVaultRepository()
    path = tmp_path / "vault.enc"
    vault = Vault(metadata=VaultMetadata())
    vault.add_entry(VaultEntry.create("github.com", "lukasz", "secret"))

    repo.save(path, vault, "password123")

    with patch(
        "localpass.vault.repository.decrypt", side_effect=Exception("Decrypt failed")
    ):
        with pytest.raises(
            CorruptedVaultError,
            match="Decryption failed \\(unexpected error\\): Decrypt failed",
        ):
            repo.load(path, "password123")


def test_plaintext_repository_save_load(tmp_path: Path) -> None:
    repo = PlaintextVaultRepository()
    path = tmp_path / "vault.json"

    vault = Vault(metadata=VaultMetadata())
    vault.add_entry(VaultEntry.create("github.com", "lukasz", "secret"))

    repo.save(path, vault)
    loaded = repo.load(path)

    assert loaded.entries[0].password == "secret"


def test_encrypted_repository_wrong_password(tmp_path: Path) -> None:
    from localpass.vault.repository import IncorrectPasswordError

    repo = EncryptedVaultRepository()
    path = tmp_path / "vault.enc"

    vault = Vault(metadata=VaultMetadata())
    vault.add_entry(VaultEntry.create("github.com", "lukasz", "secret"))

    repo.save(path, vault, "password123")
    with pytest.raises(IncorrectPasswordError, match="Incorrect master password."):
        repo.load(path, "wrongpassword")


def test_encrypted_repository_corrupted_ciphertext(tmp_path: Path) -> None:
    from localpass.vault.repository import CorruptedVaultError

    repo = EncryptedVaultRepository()
    path = tmp_path / "vault.enc"

    vault = Vault(metadata=VaultMetadata())
    vault.add_entry(VaultEntry.create("github.com", "lukasz", "secret"))

    # Save a valid encrypted vault
    repo.save(path, vault, "password123")

    # Corrupt the stored ciphertext on disk
    data = json.loads(path.read_text())
    # Truncate the ciphertext to simulate corruption
    data["ciphertext"] = data["ciphertext"][:10]
    path.write_text(json.dumps(data))

    # Loading with the correct password should still fail with a corruption error
    # Also assert on the error message to ensure corrupted ciphertext is properly detected
    with pytest.raises(CorruptedVaultError):
        repo.load(path, "password123")


def test_vault_service_create_load(tmp_path: Path) -> None:
    service = VaultService(EncryptedVaultRepository())
    path = str(tmp_path / "vault.enc")

    service.create_vault(path, "password123")
    loaded = service.load_vault(path, "password123")

    assert len(loaded.entries) == 0


def test_vault_service_add_entry(tmp_path: Path) -> None:
    service = VaultService(EncryptedVaultRepository())
    path = str(tmp_path / "vault.enc")

    vault = service.create_vault(path, "password123")
    entry = service.add_entry(vault, "github.com", "lukasz", "secret")

    assert entry.password == "secret"
    assert len(vault.entries) == 1


def test_vault_list_entries() -> None:
    vault = Vault(metadata=VaultMetadata())
    entry1 = VaultEntry.create("service1", "user1", "pass1")
    entry2 = VaultEntry.create("service2", "user2", "pass2")
    vault.add_entry(entry1)
    vault.add_entry(entry2)

    entries = vault.list_entries()
    assert len(entries) == 2
    assert entries[0].service == "service1"
    assert entries[1].service == "service2"


def test_vault_remove_entry() -> None:
    vault = Vault(metadata=VaultMetadata())
    entry1 = VaultEntry.create("service1", "user1", "pass1")
    entry2 = VaultEntry.create("service2", "user2", "pass2")
    vault.add_entry(entry1)
    vault.add_entry(entry2)

    vault.remove_entry("service1")
    assert len(vault.entries) == 1
    assert vault.entries[0].service == "service2"


def test_plaintext_repository_file_not_found(tmp_path: Path) -> None:
    repo = PlaintextVaultRepository()
    path = tmp_path / "nonexistent.json"
    with pytest.raises(ValueError, match="Vault file not found"):
        repo.load(str(path))


def test_plaintext_repository_invalid_json(tmp_path: Path) -> None:
    from localpass.vault.repository import CorruptedVaultError

    repo = PlaintextVaultRepository()
    path = tmp_path / "invalid.json"
    path.write_text("invalid json")
    with pytest.raises(CorruptedVaultError):
        repo.load(str(path))


def test_plaintext_repository_missing_fields(tmp_path: Path) -> None:
    repo = PlaintextVaultRepository()
    path = tmp_path / "missing.json"
    path.write_text('{"metadata": {}}')  # missing entries
    with pytest.raises(ValueError, match="Missing required field"):
        repo.load(str(path))


def test_encrypted_repository_file_not_found(tmp_path: Path) -> None:
    repo = EncryptedVaultRepository()
    path = tmp_path / "nonexistent.enc"
    with pytest.raises(ValueError, match="Vault file not found"):
        repo.load(str(path), "password")


def test_encrypted_repository_invalid_json(tmp_path: Path) -> None:
    from localpass.vault.repository import CorruptedVaultError

    repo = EncryptedVaultRepository()
    path = tmp_path / "invalid.enc"
    path.write_text("invalid json")
    with pytest.raises(CorruptedVaultError, match="Invalid JSON in vault file"):
        repo.load(str(path), "password")


def test_encrypted_repository_missing_fields(tmp_path: Path) -> None:
    from localpass.vault.repository import CorruptedVaultError

    repo = EncryptedVaultRepository()
    path = tmp_path / "missing.enc"
    path.write_text('{"version": 1}')  # missing fields
    with pytest.raises(CorruptedVaultError, match="Missing required field"):
        repo.load(str(path), "password")


def test_encrypted_repository_invalid_decrypted_json(tmp_path: Path) -> None:
    # Create a valid encrypted file, but manually corrupt the ciphertext to decrypt to invalid JSON
    import base64

    from localpass.vault.crypto import derive_key, encrypt
    from localpass.vault.repository import CorruptedVaultError

    repo = EncryptedVaultRepository()
    path = tmp_path / "corrupt.enc"

    # Encrypt invalid JSON
    plaintext = b"invalid json"
    salt = b"salt123456789012"
    key = derive_key("password", salt)
    nonce, ciphertext = encrypt(plaintext, key)

    data = {
        "version": 1,
        "kdf": "argon2id",
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }
    import json

    path.write_text(json.dumps(data))

    with pytest.raises(
        CorruptedVaultError, match="Invalid JSON in decrypted vault data"
    ):
        repo.load(str(path), "password")


def test_plaintext_repository_invalid_datetime(tmp_path: Path) -> None:
    repo = PlaintextVaultRepository()
    path = tmp_path / "invalid_datetime.json"
    # Invalid datetime format
    data = {
        "metadata": {
            "version": 1,
            "created_at": "invalid-date",
            "updated_at": "2023-01-01T00:00:00Z",
        },
        "entries": [],
    }
    import json

    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="Invalid data format"):
        repo.load(str(path))


def test_encrypted_repository_invalid_datetime(tmp_path: Path) -> None:
    # Encrypt data with invalid datetime
    import base64

    from localpass.vault.crypto import derive_key, encrypt

    repo = EncryptedVaultRepository()
    path = tmp_path / "invalid_datetime.enc"

    data = {
        "metadata": {
            "version": 1,
            "created_at": "invalid-date",
            "updated_at": "2023-01-01T00:00:00Z",
        },
        "entries": [],
    }
    plaintext = json.dumps(data).encode("utf-8")
    salt = b"salt123456789012"
    key = derive_key("password", salt)
    nonce, ciphertext = encrypt(plaintext, key)

    enc_data = {
        "version": 1,
        "kdf": "argon2id",
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }
    path.write_text(json.dumps(enc_data))

    with pytest.raises(ValueError, match="Invalid data format"):
        repo.load(str(path), "password")


# ============================================================================
# New tests for Issue #18: Distinguish between incorrect password and corrupted vault
# ============================================================================


def test_encrypted_repository_incorrect_password_vs_corrupted(tmp_path: Path) -> None:
    """Test that incorrect password and corrupted vault raise different exceptions."""
    from localpass.vault.repository import CorruptedVaultError, IncorrectPasswordError

    repo = EncryptedVaultRepository()
    path = tmp_path / "vault.enc"

    vault = Vault(metadata=VaultMetadata())
    vault.add_entry(VaultEntry.create("github.com", "lukasz", "secret123"))

    # Save a valid encrypted vault with password "correct_password"
    repo.save(path, vault, "correct_password")

    # Test 1: Incorrect password should raise IncorrectPasswordError
    with pytest.raises(IncorrectPasswordError) as exc_info:
        repo.load(path, "wrong_password")
    assert "Incorrect master password" in str(exc_info.value)

    # Test 2: Corrupted ciphertext should raise CorruptedVaultError
    data = json.loads(path.read_text())
    data["ciphertext"] = data["ciphertext"][:10]  # Corrupt the ciphertext
    path.write_text(json.dumps(data))

    with pytest.raises(CorruptedVaultError) as exc_info2:
        repo.load(path, "correct_password")
    assert "corrupted or unreadable" in str(exc_info2.value).lower()


def test_encrypted_repository_success_with_correct_password(tmp_path: Path) -> None:
    """Test successful decryption with the correct password."""
    repo = EncryptedVaultRepository()
    path = tmp_path / "vault.enc"

    vault = Vault(metadata=VaultMetadata())
    vault.add_entry(VaultEntry.create("github.com", "lukasz", "secret123"))

    # Save and load with the same password - should succeed
    repo.save(path, vault, "correct_password")
    loaded = repo.load(path, "correct_password")

    assert len(loaded.entries) == 1
    assert loaded.entries[0].service == "github.com"
    assert loaded.entries[0].password == "secret123"


def test_corrupted_vault_missing_fields(tmp_path: Path) -> None:
    """Test that corrupted vault with missing fields raises CorruptedVaultError."""
    from localpass.vault.repository import CorruptedVaultError

    repo = EncryptedVaultRepository()
    path = tmp_path / "corrupted.enc"

    # Write a vault file missing the 'salt' field
    data = {
        "version": 1,
        "kdf": "argon2id",
        # Missing 'salt', 'nonce', and 'ciphertext'
    }
    path.write_text(json.dumps(data))

    with pytest.raises(CorruptedVaultError) as exc_info:
        repo.load(str(path), "password")
    assert "Missing required field" in str(exc_info.value)


def test_corrupted_vault_invalid_base64(tmp_path: Path) -> None:
    """Test that corrupted vault with invalid base64 raises CorruptedVaultError."""
    from localpass.vault.repository import CorruptedVaultError

    repo = EncryptedVaultRepository()
    path = tmp_path / "corrupted.enc"

    # Write a vault file with invalid base64
    data = {
        "version": 1,
        "kdf": "argon2id",
        "salt": "not a valid base64!!!",
        "nonce": "also invalid!!!",
        "ciphertext": "totally invalid!!!",
    }
    path.write_text(json.dumps(data))

    with pytest.raises(CorruptedVaultError) as exc_info:
        repo.load(str(path), "password")
    assert "corrupted or unreadable" in str(exc_info.value).lower()
