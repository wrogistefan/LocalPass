# LocalPass

[![codecov](https://codecov.io/gh/wrogistefan/LocalPass/branch/main/graph/badge.svg)](https://codecov.io/gh/wrogistefan/LocalPass)

**Local-first, offline password manager with zero cloud, zero telemetry, and fully open-source.**

## 🔐 Project Description

LocalPass is a minimal, offline password manager designed for local-first usage. It stores your vault exclusively on your device, with no cloud integration, telemetry, or user accounts. The project emphasizes transparency, simplicity, and security through open-source development.

### Key Features

- **🔒 Encrypted Vault**: Uses Argon2id for key derivation and AES-GCM for encryption
- **💻 Cross-platform**: Works on Windows, macOS, and Linux
- **📦 Zero Cloud**: No cloud sync, no telemetry, no remote storage
- **📖 Open-Source**: Fully transparent codebase under Apache License 2.0

## ✨ Features Included in v0.1.0

- **Encrypted vault** using Argon2id + AES-GCM
- **CLI commands**: `init`, `add`, `list`, `show`, `remove`
- **Cross-platform support** for Windows, macOS, and Linux
- **Public vault format** for interoperability

## 📥 Installation

### Using pip

```bash
pip install localpass
```

### Editable mode (for development)

```bash
git clone https://github.com/wrogistefan/LocalPass.git
cd LocalPass
pip install -e .
```

## 🚀 Quickstart

### Initialize a new vault

```bash
localpass init myvault.lp
```

### Add a new entry

```bash
localpass add myvault.lp
# You'll be prompted for service, username, password, and notes
```

### List all entries

```bash
localpass list myvault.lp
```

### Show entry details

```bash
localpass show myvault.lp <entry-id>
```

### Remove an entry

```bash
localpass remove myvault.lp <entry-id>
```

## 📁 Project Structure

```
src/localpass/
├── cli.py              # CLI interface
├── vault/
│   ├── crypto.py       # Encryption/decryption
│   ├── models.py       # Data models
│   ├── repository.py   # Vault storage
│   ├── service.py      # Business logic
│   └── serialization.py # JSON serialization
└── __main__.py         # Entry point
```

## 🔧 Vault API

The `Vault` class provides the core API for managing password entries:

### Methods

- `add_entry(entry: VaultEntry) -> None`: Add a new entry to the vault.
- `list_entries() -> List[VaultEntry]`: Return a copy of all entries in the vault.
- `get_entry_by_id(entry_id: str) -> Optional[VaultEntry]`: Retrieve an entry by its unique ID, or `None` if not found.
- `remove_entry(service: str) -> None`: Remove all entries that match the specified service name.
- `remove_entry_by_id(entry_id: str) -> None`: Remove the entry with the specified unique ID. Raises `ValueError` if the entry does not exist.

### Key Differences

- `remove_entry(service)` performs a bulk removal of all entries for a given service, which is useful for cleaning up multiple accounts.
- `remove_entry_by_id(entry_id)` provides granular deletion of a single entry by its ID, intended for precise CLI operations. It ensures the entry exists before removal.

This API is designed for programmatic use and powers the LocalPass CLI.

##  Documentation

- [📖 User Manual](docs/USER_MANUAL.md) - Full CLI usage guide
- [🔐 Security](docs/SECURITY.md) - Threat model and encryption details
- [📜 Changelog](CHANGELOG.md) - Release history

## 🔐 Security

LocalPass prioritizes security through:
- **Argon2id** key derivation with memory-hard parameters
- **AES-GCM** authenticated encryption
- **Zero telemetry** and no cloud dependencies

For detailed security information, see [docs/SECURITY.md](docs/SECURITY.md).

## ⚠️ Security Notes

LocalPass supports different repository types for vault storage, each with varying security levels:

- **EncryptedVaultRepository**: Recommended for production use. Stores vault data encrypted using Argon2id key derivation and AES-GCM encryption, ensuring data confidentiality.
- **PlaintextVaultRepository**: Stores vault data in plaintext and is **unsafe for production environments**. It is intended only for testing, debugging, or isolated environments where security is not a concern. Using this repository will emit a runtime warning.

Always use `EncryptedVaultRepository` for any real-world scenarios requiring data protection.

## 📄 License

This project is licensed under the Apache License 2.0.
See the [LICENSE](LICENSE) file for full details.

## 👤 Author

Created by **Łukasz Perek** — local-first software enthusiast.
