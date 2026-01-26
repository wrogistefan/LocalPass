<p align="center">
  <img src="https://static.pepy.tech/badge/localpass" alt="Downloads">
  <img src="https://img.shields.io/pypi/v/localpass" alt="PyPI Version">
  <img src="https://img.shields.io/pypi/pyversions/localpass" alt="Python Versions">
  <img src="https://img.shields.io/github/license/wrogistefan/LocalPass" alt="License">
  <img src="https://img.shields.io/github/actions/workflow/status/wrogistefan/LocalPass/tests.yml?label=tests" alt="Tests">
  <img src="https://img.shields.io/github/last-commit/wrogistefan/LocalPass" alt="Last Commit">
</p>

<p align="center">
  <strong>Local-first, offline password manager.</strong><br>
  Zero cloud. Zero telemetry. Fully open-source.
  Designed for security, simplicity, and complete user control.
</p>

<p align="center">
  <a href="https://pypi.org/project/localpass/">PyPI</a> •
  <a href="https://github.com/wrogistefan/LocalPass">GitHub</a>
</p>

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
- **✅ High Test Coverage**: 99% test coverage with comprehensive validation
- **🔧 Shell Compatibility**: Verified on Windows PowerShell and Unix shells (WSL/bash)

## ✨ Features Included in v0.2.0

- Added optional, fully manual HIBP password check (k‑anonymity API)
- Added new Security Model section to README
- Updated README header with professional badges
- Improved documentation structure and clarity

## Security Model

LocalPass follows a strict local‑first and offline‑first security philosophy.
All operations happen entirely on the user’s device, and no data is ever sent to external services.

### Core Principles
- **Local‑only encryption** — all vault data is encrypted client‑side using Argon2id and AES‑256‑GCM.
- **Offline‑first** — the application works fully without network access.
- **Zero cloud** — no sync, no remote storage, no accounts, no telemetry.
- **Deterministic security** — the vault file contains everything needed to decrypt the data; nothing is stored elsewhere.

### Threat Model (High‑Level)
LocalPass protects against:
- offline brute‑force attacks on the vault file,
- filesystem snooping,
- accidental disclosure,
- network interception (no network operations exist).

LocalPass cannot protect against:
- keyloggers or malware on the user’s system,
- shoulder surfing,
- physical access combined with password knowledge,
- side‑channel attacks.

### Full Security Documentation
For detailed cryptographic parameters, vault format, repository types, and responsible disclosure guidelines, see:

👉 **[docs/SECURITY.md](docs/SECURITY.md)**

## Optional HIBP Password Check

LocalPass includes an optional, fully manual password check using the Have I Been Pwned (HIBP) k‑anonymity API.

This feature is:
- **optional** — disabled by default,
- **manual** — only executed when explicitly requested by the user,
- **non‑blocking** — it never prevents vault creation,
- **privacy‑preserving** — only the first 5 characters of the SHA‑1 hash are sent,
- **philosophy‑aligned** — no automatic network calls, ever.

This keeps LocalPass fully offline‑first while still offering a useful security tool for users who want it.

## 🚀 What's New in 0.2.0

- Introduced optional manual HIBP password check
- Added high-level Security Model summary to README
- Cleaned up and reorganized documentation
- Updated header and removed outdated links

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
# You'll be prompted to enter and confirm a master password
```

### Add a new entry

```bash
localpass add myvault.lp --id 1
# You'll be prompted for master password, service, username, password (with confirmation), and notes
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

### Check password against breaches

```bash
localpass hibp-check
# You'll be prompted to confirm the network request, then enter a password to check
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

### EncryptedVaultRepository (Recommended)

- **Encryption Model**: Uses Argon2id for password-based key derivation (32-byte key, 100 MiB memory, 2 iterations, 8 parallelism) followed by AES-256-GCM authenticated encryption.
- **Assumptions**: Relies on the strength of your master password and the security of your local system. Assumes no malware/keyloggers are present.
- **Limitations**: Does not protect against system compromise, physical theft of both vault file and password, or side-channel attacks.
- **Key Management**: Your master password is the only key. It must be strong (12+ characters, mixed case, numbers, symbols), unique, and never stored or shared. The password is stretched into a cryptographic key using Argon2id, making brute-force attacks computationally expensive.
- **When to Use**: Always for production, real-world password management, or any scenario where data confidentiality matters.
- **Why Required**: Provides robust encryption ensuring vault contents remain confidential at rest and in transit (when backed up).

### PlaintextVaultRepository (Unsafe)

- **Encryption Model**: None - stores all data in plaintext JSON.
- **Why Unsafe**: Exposes all passwords, usernames, and notes to anyone with file access. Suitable only for testing, debugging, or air-gapped development environments.
- **Warning**: Emits a runtime warning when used.

Always use `EncryptedVaultRepository` for any real-world scenarios requiring data protection.

## 📄 License

This project is licensed under the Apache License 2.0.
See the [LICENSE](LICENSE) file for full details.

## 👤 Author

Created by **Łukasz Perek** — local-first software enthusiast.
