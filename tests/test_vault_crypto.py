import json
from pathlib import Path

import pytest

from localpass.vault.crypto import decrypt, derive_key, encrypt
from localpass.vault.models import Vault, VaultEntry, VaultMetadata
from localpass.vault.repository import (
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


def test_plaintext_repository_save_load(tmp_path: Path) -> None:
    repo = PlaintextVaultRepository()
    path = tmp_path / "vault.json"

    vault = Vault(metadata=VaultMetadata())
    vault.add_entry(VaultEntry.create("github.com", "lukasz", "secret"))

    repo.save(path, vault)
    loaded = repo.load(path)

    assert loaded.entries[0].password == "secret"


def test_encrypted_repository_wrong_password(tmp_path: Path) -> None:
    repo = EncryptedVaultRepository()
    path = tmp_path / "vault.enc"

    vault = Vault(metadata=VaultMetadata())
    vault.add_entry(VaultEntry.create("github.com", "lukasz", "secret"))

    repo.save(path, vault, "password123")
    with pytest.raises(ValueError, match="Invalid password or corrupted vault"):
        repo.load(path, "wrongpassword")


def test_encrypted_repository_corrupted_ciphertext(tmp_path: Path) -> None:
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

    # Loading with the correct password should still fail with a decryption error
    with pytest.raises(ValueError, match="Invalid password or corrupted vault"):
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
    repo = PlaintextVaultRepository()
    path = tmp_path / "invalid.json"
    path.write_text("invalid json")
    with pytest.raises(ValueError, match="Invalid JSON in vault file"):
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
    repo = EncryptedVaultRepository()
    path = tmp_path / "invalid.enc"
    path.write_text("invalid json")
    with pytest.raises(ValueError, match="Invalid JSON in vault file"):
        repo.load(str(path), "password")


def test_encrypted_repository_missing_fields(tmp_path: Path) -> None:
    repo = EncryptedVaultRepository()
    path = tmp_path / "missing.enc"
    path.write_text('{"version": 1}')  # missing fields
    with pytest.raises(ValueError, match="Missing required field"):
        repo.load(str(path), "password")


def test_encrypted_repository_invalid_decrypted_json(tmp_path: Path) -> None:
    # Create a valid encrypted file, but manually corrupt the ciphertext to decrypt to invalid JSON
    import base64

    from localpass.vault.crypto import derive_key, encrypt

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

    with pytest.raises(ValueError, match="Invalid JSON in decrypted vault data"):
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
