# LocalPass User Manual

## 📖 Introduction

Welcome to LocalPass! This manual provides comprehensive instructions for using LocalPass, a local-first, offline password manager.

## 📥 Installation

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

### Installation Methods

#### Using pip (recommended)

```bash
pip install localpass
```

#### Development installation

```bash
git clone https://github.com/wrogistefan/LocalPass.git
cd LocalPass
pip install -e .
```

## 🚀 CLI Usage

LocalPass provides a command-line interface with the following commands:

### `localpass init <path>`

Initialize a new encrypted vault.

**Usage:**
```bash
localpass init myvault.lp
```

**Process:**
1. You'll be prompted to enter and confirm a master password (cannot be empty)
2. If the password is left empty, you'll be prompted to enter a value
3. A new vault file will be created at the specified path
4. The vault uses Argon2id + AES-GCM encryption

**Example:**
```bash
$ localpass init secure_vault.lp
Enter master password: 
Confirm master password: 
Vault initialized successfully.
```

### `localpass add <path>`

Add a new entry to an existing vault.

**Usage:**
```bash
localpass add myvault.lp
```

**Process:**
1. Enter your master password to unlock the vault
2. Provide required entry details: Service, Username, Password (all required and cannot be empty), Notes (optional)
3. If a required field is left empty, you'll be prompted to enter a value
4. The entry will be added and assigned a unique ID

**Example:**
```bash
$ localpass add myvault.lp
Enter master password: 
Service: GitHub
Username: myusername
Password: 
Notes (optional): Personal account
Entry added with ID: abc123
```

### `localpass list <path>`

List all entries in a vault.

**Usage:**
```bash
localpass list myvault.lp
```

**Process:**
1. Enter your master password to unlock the vault
2. All entries will be displayed in a table format

**Example:**
```bash
$ localpass list myvault.lp
Enter master password: 
ID      Service     Username    Tags
abc123  GitHub      myusername 
def456  Email       contact@me.com
```

### `localpass show <path> <id>`

Show detailed information about a specific entry.

**Usage:**
```bash
localpass show myvault.lp abc123
```

**Process:**
1. Enter your master password to unlock the vault
2. Detailed information about the specified entry will be displayed

**Example:**
```bash
$ localpass show myvault.lp abc123
Enter master password: 
Service: GitHub
Username: myusername
Password: mysecretpassword
Notes: Personal account
Tags: 
Created at: 2026-01-13 01:56:00
Updated at: 2026-01-13 01:56:00
```

### `localpass remove <path> <id>`

Remove an entry from a vault.

**Usage:**
```bash
localpass remove myvault.lp abc123
```

**Process:**
1. Enter your master password to unlock the vault
2. The specified entry will be permanently removed

**Example:**
```bash
$ localpass remove myvault.lp abc123
Enter master password: 
Entry removed successfully.
```

## 🗃️ Vault File Format

LocalPass vault files use a simple but secure format:

### File Structure

```
VAULT_FILE = SALT || NONCE || CIPHERTEXT || AUTH_TAG
```

### Components

- **SALT**: 16-byte random salt for key derivation
- **NONCE**: 12-byte random nonce for AES-GCM
- **CIPHERTEXT**: Encrypted JSON data containing all entries
- **AUTH_TAG**: 16-byte authentication tag for integrity

### JSON Data Structure

```json
{
  "version": 1,
  "created_at": "2026-01-13T01:56:00",
  "updated_at": "2026-01-13T01:56:00",
  "entries": [
    {
      "id": "abc123",
      "service": "GitHub",
      "username": "myusername",
      "password": "encrypted_password",
      "notes": "Personal account",
      "tags": [],
      "created_at": "2026-01-13T01:56:00",
      "updated_at": "2026-01-13T01:56:00"
    }
  ]
}
```

#### Serialization Guarantees

- **Stable JSON Structure**: The JSON schema is stable and backwards-compatible. New fields may be added in future versions, but existing fields will not be removed or changed in meaning.
- **ISO8601 Timestamps**: All timestamps (`created_at`, `updated_at`) are stored in ISO 8601 format with UTC timezone (e.g., `2026-01-13T01:56:00`). Invalid or non-ISO8601 timestamps will cause deserialization to fail with a clear error message.
- **Deterministic Ordering**: Entries are serialized in the order they appear in the vault. The JSON structure does not guarantee sorted ordering unless explicitly sorted by the application.
- **Default Values for Missing Fields**: If the `tags` field is missing from an entry, it defaults to an empty list (`[]`). Other optional fields like `notes` default to `null` if absent.

## ⚠️ Security Considerations

### Repository Types

LocalPass supports different repository implementations for vault storage:

- **EncryptedVaultRepository**: The default and recommended option. Uses strong encryption (Argon2id + AES-GCM) to protect your data.
- **PlaintextVaultRepository**: Stores vault data in unencrypted JSON format. **This is unsafe for production use** and should only be used for testing, debugging, or isolated environments where security is not a concern. Using this repository will display a warning message.

**Important**: Always use the encrypted repository for any real-world password management to ensure your data remains confidential.

## ❓ Troubleshooting

### Wrong Password

**Symptom:** `Error: Invalid password or corrupted vault`

**Solution:**
1. Double-check your password
2. Ensure you're using the correct keyboard layout
3. Check for Caps Lock or Num Lock
4. If you've forgotten your password, the vault cannot be recovered

### Corrupted Vault

**Symptom:** `Error: Invalid vault format` or `Error: Decryption failed`

**Solution:**
1. Restore from backup if available
2. Check file integrity with `sha256sum myvault.lp`
3. Try opening on a different device
4. If corruption is confirmed, the vault may not be recoverable

### Missing File

**Symptom:** `Error: File not found`

**Solution:**
1. Check the file path is correct
2. Verify the file exists with `ls myvault.lp` (Linux/macOS) or `dir myvault.lp` (Windows)
3. Check for accidental deletion or movement
4. Restore from backup if available

### Windows PATH Issues

**Symptom:** `localpass: command not found`

**Solution:**
1. Ensure Python is added to your PATH
2. Try reinstalling: `pip install --force-reinstall localpass`
3. Use the full path: `python -m localpass init myvault.lp`
4. Restart your terminal or command prompt

## ❔ FAQ

### Is LocalPass secure?

LocalPass uses industry-standard cryptography (Argon2id + AES-GCM) and follows security best practices. However, no software can guarantee 100% security. Always use a strong master password and keep your system secure.

### Can I sync my vault between devices?

LocalPass does not provide built-in sync functionality. You can manually copy your vault file between devices, but ensure secure transfer methods (e.g., encrypted USB drives, secure cloud storage with end-to-end encryption).

### What happens if I forget my master password?

There is no password recovery mechanism. If you forget your master password, your vault cannot be recovered. Make sure to remember your password or store it securely.

### Can I import/export from other password managers?

Currently, LocalPass does not support direct import/export from other password managers. This feature may be added in future versions.

### How do I backup my vault?

Simply copy the vault file to a secure location:
```bash
cp myvault.lp /backup/location/myvault_backup.lp
```

### Can I use LocalPass on mobile devices?

LocalPass is currently designed for desktop use. Mobile support may be added in future versions.

### How do I update LocalPass?

```bash
pip install --upgrade localpass
```

### Is there a GUI version?

LocalPass is currently CLI-only. A graphical interface may be developed in future versions.

### How can I contribute?

Contributions are welcome! See the GitHub repository for contribution guidelines and open issues.