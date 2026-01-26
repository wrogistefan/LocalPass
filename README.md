<p align="center">
  <img src="https://static.pepy.tech/badge/localpass" alt="Downloads">
  <img src="https://img.shields.io/pypi/v/localpass" alt="PyPI Version">
  ![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)
  <img src="https://img.shields.io/github/license/wrogistefan/LocalPass" alt="License">
  <img src="https://img.shields.io/github/actions/workflow/status/wrogistefan/LocalPass/ci.yml?label=tests" alt="Tests">
  <img src="https://img.shields.io/github/last-commit/wrogistefan/LocalPass" alt="Last Commit">
  <a href="https://codecov.io/gh/wrogistefan/LocalPass"><img src="https://codecov.io/gh/wrogistefan/LocalPass/branch/main/graph/badge.svg" alt="codecov"></a>
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

Local-first, offline password manager. Zero cloud. Zero telemetry. Fully open-source.

## Why LocalPass?

Most password managers rely on cloud sync, telemetry, or proprietary storage.
LocalPass takes the opposite approach:
- 100% offline
- 100% local storage
- 100% open-source
- no accounts, no tracking, no vendor lock-in
If you want full control over your vault — LocalPass is built for you.

## Quickstart

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

## Installation

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

## Key Features

- **🔒 Encrypted Vault**: Uses Argon2id for key derivation and AES-GCM for encryption
- **💻 Cross-platform**: Works on Windows, macOS, and Linux
- **📦 Zero Cloud**: No cloud sync, no telemetry, no remote storage
- **📖 Open-Source**: Fully transparent codebase under Apache License 2.0
- **✅ High Test Coverage**: 99% test coverage with comprehensive validation
- **🔧 Shell Compatibility**: Verified on Windows PowerShell and Unix shells (WSL/bash)

## Security Model

LocalPass follows a strict local‑first and offline‑first security philosophy.
All operations happen entirely on the user's device, and no data is ever sent to external services.

- **Local‑only encryption** — all vault data is encrypted client‑side using Argon2id and AES‑256‑GCM.
- **Offline‑first** — the application works fully without network access.
- **Zero cloud** — no sync, no remote storage, no accounts, no telemetry.
- **Deterministic security** — the vault file contains everything needed to decrypt the data; nothing is stored elsewhere.

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

## Project Structure

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

## Vault API

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

## License

This project is licensed under the Apache License 2.0.
See the [LICENSE](LICENSE) file for full details.
