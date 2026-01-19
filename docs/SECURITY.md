# Security Documentation

## 🔐 Threat Model

LocalPass is designed with a specific threat model in mind:

### ✅ Protected Against

- **Offline attacks**: Vault files are encrypted with strong cryptography
- **Casual snooping**: No plaintext storage of sensitive data
- **Data breaches**: No cloud storage or telemetry
- **Network interception**: All operations are local-only

### ❌ Not Protected Against

- **Keyloggers/malware**: If your system is compromised, LocalPass cannot protect you
- **Shoulder surfing**: Password entry is visible during input
- **Physical theft**: If an attacker has your vault file AND your password
- **Side-channel attacks**: Timing attacks on cryptographic operations

## 🔐 Encryption Details

### Key Derivation (Argon2id)

LocalPass uses Argon2id for password-based key derivation with the following parameters:

- **Algorithm**: Argon2id (hybrid of Argon2i and Argon2d)
- **Output length**: 32 bytes (256 bits)
- **Iterations**: 2 passes over memory
- **Memory cost**: 102,400 KiB (100 MiB)
- **Parallelism**: 8 lanes
- **Salt**: Random 16-byte salt per vault

These parameters are chosen to provide strong resistance against both GPU and ASIC attacks while maintaining reasonable performance on modern hardware.

### Encryption (AES-GCM)

- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key size**: 256 bits
- **Nonce**: 12-byte random nonce per encryption operation
- **Authentication**: Built-in authentication tag for integrity

### Vault File Format

```
VAULT_FILE = SALT || NONCE || CIPHERTEXT || AUTH_TAG
```

Where:
- `SALT`: 16-byte random salt for key derivation
- `NONCE`: 12-byte random nonce for AES-GCM
- `CIPHERTEXT`: Encrypted vault data
- `AUTH_TAG`: 16-byte authentication tag for integrity verification

## 📁 Repository Types and Security

LocalPass supports different repository implementations for vault storage, each with distinct security properties:

### EncryptedVaultRepository (Recommended)

- **Security Level**: High
- **Encryption**: Uses Argon2id key derivation and AES-GCM encryption
- **Use Case**: Production environments, real-world password management
- **Risks**: None for encrypted data at rest; standard cryptographic protections apply

### PlaintextVaultRepository (Development Only)

- **Security Level**: None
- **Encryption**: Stores vault data in plaintext JSON format
- **Use Case**: Testing, debugging, or isolated development environments only
- **Risks**: Complete exposure of all sensitive data (passwords, usernames, notes) to anyone with file access
- **Warning**: This repository emits a runtime `UserWarning` when instantiated and is explicitly marked as unsafe for production use

**Critical**: Never use `PlaintextVaultRepository` in any environment where data confidentiality is required. It exists solely for development and testing purposes.

## 🚫 What LocalPass Does NOT Do

### No Cloud Integration

- ❌ No cloud sync
- ❌ No online backup
- ❌ No multi-device synchronization
- ❌ No account system or user registration

### No Telemetry

- ❌ No usage analytics
- ❌ No error reporting
- ❌ No crash reports
- ❌ No automatic updates

### No Remote Storage

- ❌ No server-side storage
- ❌ No database backends
- ❌ No third-party integrations

## 🛡️ Responsible Disclosure Process

If you discover a security vulnerability in LocalPass, please follow this process:

1. **Do not disclose publicly** until a fix is available
2. **Contact the maintainer** via email: lukasz.perek@outlook.com
3. **Provide details**: Description, reproduction steps, impact assessment
4. **Allow time**: Give at least 30 days for a fix to be developed
5. **Coordinate**: Work with the maintainer on disclosure timing

## 📋 Guidelines for Reporting Vulnerabilities

### What to Include

- Clear description of the vulnerability
- Steps to reproduce
- Impact assessment (low/medium/high/critical)
- Suggested mitigation (if available)
- Your contact information (for follow-up)

### What NOT to Do

- ❌ Do not exploit the vulnerability in production
- ❌ Do not disclose to third parties without coordination
- ❌ Do not demand compensation or rewards
- ❌ Do not use automated vulnerability scanners without permission

### Response Process

1. **Acknowledgment**: You will receive an initial response within 72 hours
2. **Assessment**: The vulnerability will be evaluated and prioritized
3. **Development**: A fix will be developed and tested
4. **Release**: The fix will be released in a new version
5. **Disclosure**: Public disclosure will be coordinated

## 🔒 Security Best Practices for Users

### Password Management

- Use a **strong master password** (12+ characters, mixed case, numbers, symbols)
- **Never reuse** your master password
- **Store securely**: Keep your vault file in a safe location
- **Backup regularly**: Make encrypted backups of your vault file

### System Security

- Keep your operating system updated
- Use antivirus/anti-malware software
- Be cautious of keyloggers and screen capture malware
- Use full-disk encryption on your devices

### Vault Management

- Store vault files only on trusted devices
- Use secure deletion when removing old vault files
- Consider using a hardware security key for additional protection
- Regularly audit your vault entries