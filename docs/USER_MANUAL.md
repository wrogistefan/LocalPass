# LocalPass User Manual

## 📖 Introduction

Welcome to LocalPass! This manual provides comprehensive instructions for using LocalPass, a local-first, offline password manager. Verified to work on Windows PowerShell and Unix shells (WSL/bash).

LocalPass v0.3.0 introduces automation features including JSON output mode and non-interactive operation flags for scripting and CI/CD integration.

## 📥 Installation

### Prerequisites

- Python 3.11 or higher
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

LocalPass provides a command-line interface with the following global options and commands.

### Global Options

| Option | Description |
|--------|-------------|
| `--json` | Output results in JSON format for scripting |
| `--version` | Show version information |
| `--help` | Show help message |

### `--json` Output Mode

When `--json` is used, all output is formatted as JSON with the following structure:

```json
{
  "status": "ok" | "error",
  "version": "0.3.0",
  "action": "command_name",
  "data": { ... }
}
```

**Important**: In JSON mode, password prompts cannot be displayed. Commands requiring passwords will fail in JSON mode unless combined with `--yes` flag.

### `--yes` / `-y` Flag

The `--yes` or `-y` flag skips all confirmation prompts:

- Skips weak password confirmation during vault initialization
- Skips overwrite confirmation when vault exists
- Automatically confirms HIBP API requests
- Auto-confirms in JSON mode (implicit behavior)

Use with caution in scripts, especially for vault initialization.

## 📦 Command Reference

### `localpass init <path>`

Initialize a new encrypted vault.

**Usage:**
```bash
localpass init myvault.lp
localpass init myvault.lp --yes    # Skip all confirmations
localpass init myvault.lp --json   # JSON output
```

**Process:**
1. You'll be prompted to enter a master password (cannot be empty)
2. Password strength is analyzed using zxcvbn
3. You'll see strength label, warnings, and suggestions
4. If password is weak, you'll be asked to confirm
5. You'll be prompted to confirm the master password
6. If passwords don't match, you'll be prompted to try again
7. A new vault file will be created at the specified path
8. The vault uses Argon2id + AES-GCM encryption

**Password Strength Labels:**
- 0: Very Weak
- 1: Weak
- 2: Fair
- 3: Strong
- 4: Very Strong

**Human-readable Example:**
```bash
$ localpass init secure_vault.lp
Enter new master password:
Password strength: Fair
Warning: Add another word or two
Suggestion: Capitalization doesn't help much
Suggestion: Add a few more words
Password is weak. Do you want to continue anyway? [y/N]: y
Confirm master password:
Vault initialized successfully.
```

**JSON Output Example:**
```bash
$ localpass init new_vault.lp --yes --json
{
  "status": "ok",
  "version": "0.3.0",
  "action": "init",
  "data": {
    "path": "/path/to/new_vault.lp"
  }
}
```

### `localpass add <path>`

Add a new entry to an existing vault.

**Usage:**
```bash
localpass add myvault.lp
localpass add myvault.lp --id 1    # Custom ID
localpass add myvault.lp --yes     # Skip confirmations
localpass add myvault.lp --json    # JSON output
```

**Process:**
1. Enter your master password to unlock the vault
2. Provide required entry details: Service, Username (both required and cannot be empty)
3. Enter and confirm the password (required and cannot be empty)
4. Optionally provide notes
5. The entry will be added and assigned a unique ID (or custom ID if specified)

**Human-readable Example:**
```bash
$ localpass add myvault.lp
Enter master password:
Service: GitHub
Username: myusername
Enter password:
Confirm password:
Notes (optional): Personal account
Entry added with ID: abc123
```

**JSON Output Example:**
```bash
$ localpass add myvault.lp --json
{
  "status": "ok",
  "version": "0.3.0",
  "action": "add",
  "data": {
    "entry_id": "abc123",
    "service": "GitHub"
  }
}
```

### `localpass list <path>`

List all entries in a vault.

**Usage:**
```bash
localpass list myvault.lp
localpass list myvault.lp --json    # JSON output
```

**Process:**
1. Enter your master password to unlock the vault
2. All entries will be displayed

**Human-readable Example:**
```bash
$ localpass list myvault.lp
Enter master password:
ID      Service     Username    Tags
abc123  GitHub      myusername
def456  Email       contact@me.com
```

**JSON Output Example:**
```bash
$ localpass list myvault.lp --json
{
  "status": "ok",
  "version": "0.3.0",
  "action": "list",
  "data": {
    "entries": [
      {
        "id": "abc123",
        "service": "GitHub",
        "username": "myusername",
        "tags": []
      },
      {
        "id": "def456",
        "service": "Email",
        "username": "contact@me.com",
        "tags": []
      }
    ]
  }
}
```

### `localpass show <path> <id>`

Show detailed information about a specific entry.

**Usage:**
```bash
localpass show myvault.lp abc123
localpass show myvault.lp abc123 --show-password    # Reveal password
localpass show myvault.lp abc123 --json             # JSON output
```

**Process:**
1. Enter your master password to unlock the vault
2. Detailed information about the specified entry will be displayed

**Human-readable Example:**
```bash
$ localpass show myvault.lp abc123
Enter master password:
Service: GitHub
Username: myusername
Password: [hidden] (re-run with --show-password to display)
Notes: Personal account
Tags:
Created at: 2026-01-13 01:56:00
Updated at: 2026-01-13 01:56:00
```

**JSON Output Example:**
```bash
$ localpass show myvault.lp abc123 --show-password --json
{
  "status": "ok",
  "version": "0.3.0",
  "action": "show",
  "data": {
    "id": "abc123",
    "service": "GitHub",
    "username": "myusername",
    "password": "mysecretpassword",
    "notes": "Personal account",
    "tags": [],
    "created_at": "2026-01-13T01:56:00",
    "updated_at": "2026-01-13T01:56:00"
  }
}
```

**Error Response (JSON mode, missing entry):**
```bash
$ localpass show myvault.lp nonexistent --json
{
  "status": "error",
  "version": "0.3.0",
  "action": "show",
  "data": {
    "message": "Entry with ID 'nonexistent' not found."
  }
}
```

### `localpass edit <path> <id>`

Edit entry fields in the vault.

**Usage:**
```bash
localpass edit myvault.lp abc123
localpass edit myvault.lp abc123 --yes    # Skip confirmations
localpass edit myvault.lp abc123 --json   # JSON output
```

**Process:**
1. Enter your master password to unlock the vault
2. Current values are shown as defaults
3. Press Enter to keep current value, or type new value
4. Confirm if you want to change the password
5. The entry will be updated

**Human-readable Example:**
```bash
$ localpass edit myvault.lp abc123
Enter master password:
Service [GitHub]:
Username [myusername]:
Change password? [y/N]: y
Enter new password:
Confirm new password:
Notes (optional) [Personal account]:
Entry updated: abc123
```

**JSON Output Example:**
```bash
$ localpass edit myvault.lp abc123 --yes --json
{
  "status": "ok",
  "version": "0.3.0",
  "action": "edit",
  "data": {
    "entry_id": "abc123"
  }
}
```

### `localpass remove <path> <id>`

Remove an entry from a vault.

**Usage:**
```bash
localpass remove myvault.lp abc123
localpass remove myvault.lp abc123 --yes    # Skip confirmation
localpass remove myvault.lp abc123 --json   # JSON output
```

**Process:**
1. Enter your master password to unlock the vault
2. The specified entry will be permanently removed

**Human-readable Example:**
```bash
$ localpass remove myvault.lp abc123
Enter master password:
Entry removed successfully.
```

**JSON Output Example:**
```bash
$ localpass remove myvault.lp abc123 --yes --json
{
  "status": "ok",
  "version": "0.3.0",
  "action": "remove",
  "data": {
    "entry_id": "abc123"
  }
}
```

### `localpass hibp-check`

Check if a password appears in known data breaches using the Have I Been Pwned (HIBP) k-anonymity API.

**Usage:**
```bash
localpass hibp-check
localpass hibp-check --yes    # Auto-confirm API request
localpass hibp-check --json   # JSON output
```

**Process:**
1. You'll be prompted to confirm the network request (required for privacy)
2. Enter the password to check (input is hidden)
3. LocalPass sends only the first 5 characters of the SHA-1 hash to the HIBP API
4. The API responds with matching hash suffixes and breach counts
5. Results are displayed locally

**Important Notes:**
- This is fully manual and optional - LocalPass never performs automatic network requests
- Only the SHA-1 prefix (5 characters) is sent; the full password and hash never leave your device
- Requires internet connection for the check
- Graceful error handling for network failures or malformed responses

**Human-readable Example (not breached):**
```bash
$ localpass hibp-check
This command checks whether a password appears in known data breaches
using the Have I Been Pwned (HIBP) k-anonymity API.

LocalPass will send ONLY the first 5 characters of the SHA-1 hash of your password.
The full password never leaves your device.

This is an optional, manual check. LocalPass never performs network requests automatically.
This action will query the HIBP API. Continue? [y/N]: y
Enter password to check:
This password was not found in the HIBP breach database.
Absence from the database does not guarantee the password is safe.
```

**Human-readable Example (breached):**
```bash
$ localpass hibp-check
This action will query the HIBP API. Continue? [y/N]: y
Enter password to check:
⚠️  This password appears in known breaches: 12345 times.
It is strongly recommended to choose a different password.
```

**JSON Output Example (success):**
```bash
$ localpass hibp-check --yes --json
{
  "status": "ok",
  "version": "0.3.0",
  "action": "hibp_check",
  "data": {
    "count": 12345,
    "breached": true
  }
}
```

**JSON Output Example (not breached):**
```bash
$ localpass hibp-check --yes --json
{
  "status": "ok",
  "version": "0.3.0",
  "action": "hibp_check",
  "data": {
    "count": 0,
    "breached": false
  }
}
```

**JSON Output Example (aborted):**
```bash
$ localpass hibp-check --json
{
  "status": "ok",
  "version": "0.3.0",
  "action": "hibp_check",
  "data": {
    "aborted": true
  }
}
```

**JSON Output Example (network error):**
```bash
$ localpass hibp-check --yes --json
{
  "status": "error",
  "version": "0.3.0",
  "action": "hibp_check",
  "data": {
    "message": "Network error: unable to reach the HIBP API."
  }
}
```

## 🤖 Automation

LocalPass supports scripting and automation with JSON output and non-interactive flags.

### Using `--json` for Scripting

The `--json` flag outputs all results in machine-readable JSON format:

```bash
#!/bin/bash
# Example: Check vault entries and process them

entries=$(localpass list myvault.lp --json)
echo "$entries" | jq -r '.data.entries[].service'
```

### Using `--yes` for Non-Interactive Mode

The `--yes` or `-y` flag skips all confirmation prompts:

```bash
#!/bin/bash
# Example: Create a vault non-interactively (use with caution)

localpass init new_vault.lp --yes
localpass add new_vault.lp --id 1 --yes
```

### Exit Code Behavior

- Exit code 0: Success
- Exit code 1: Error (invalid command, missing file, etc.)

### Complete Automation Example

```bash
#!/bin/bash
# Create a new vault and add entries non-interactively

VAULT_PATH="automation_test.lp"
MASTER_PASSWORD="testpassword123"

# Initialize vault
echo "$MASTER_PASSWORD" | localpass init "$VAULT_PATH" --yes

# Add entries
echo "$MASTER_PASSWORD" | localpass add "$VAULT_PATH" --id 1 --yes

# List entries in JSON format
localpass list "$VAULT_PATH" --json

# Clean up
rm "$VAULT_PATH"
```

**Note**: While this example shows automation capabilities, always use strong, unique master passwords in production.

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

**Symptom:** `Incorrect master password.`

**Solution:**
1. Double-check your password
2. Ensure you're using the correct keyboard layout
3. Check for Caps Lock or Num Lock
4. If you've forgotten your password, the vault cannot be recovered

### Corrupted Vault

**Symptom:** `Vault file is corrupted or unreadable.`

**Solution:**
1. Restore from backup if available
2. Check file integrity with `sha256sum myvault.lp`
3. Try opening on a different device
4. If corruption is confirmed, the vault may not be recoverable

### Missing File

**Symptom:** `Vault file not found`

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

### JSON Mode Password Error

**Symptom:** `Master password is required but cannot be prompted in JSON mode.`

**Solution:**
1. JSON mode cannot prompt for passwords
2. Use a pipe or environment variable for password input
3. Combine `--yes` with `--json` for full automation
4. Example: `echo "$PASS" | localpass add vault.lp --json`

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
