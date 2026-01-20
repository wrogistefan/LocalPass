# PR: Distinguish Between Incorrect Password and Corrupted Vault (Issue #18)

## Problem
Previously, the LocalPass CLI showed the same generic error message "Invalid password or corrupted vault" for two completely different scenarios:
1. User enters wrong master password
2. Vault file is corrupted or unreadable

This ambiguity confused users and made debugging difficult.

## Solution
Implemented proper error handling that distinguishes between:

### Incorrect Master Password
- **Exception**: `IncorrectPasswordError` (inherits from `ValueError`)
- **User Message**: "Error: Incorrect master password."
- **Root Cause**: AESGCM authentication tag verification fails (cryptography.exceptions.InvalidTag)

### Corrupted Vault File
- **Exception**: `CorruptedVaultError` (inherits from `ValueError`)
- **User Message**: "Error: Vault file is corrupted or unreadable."
- **Root Causes**: 
  - Invalid JSON formatting
  - Missing required encryption fields
  - Invalid base64 encoding
  - Decrypted data doesn't parse as valid JSON

## Implementation Details

### New Exception Classes
Two custom exception classes in `src/localpass/vault/repository.py`:
- `IncorrectPasswordError`: When decryption authentication fails
- `CorruptedVaultError`: When vault structure/format is invalid

### Enhanced Decryption Logic
Updated `EncryptedVaultRepository.load()` to:
1. Catch `json.JSONDecodeError` during vault file parsing → `CorruptedVaultError`
2. Catch `KeyError` during field extraction → `CorruptedVaultError`
3. Catch `base64` decode errors → `CorruptedVaultError`
4. Catch `InvalidTag` during decryption → `IncorrectPasswordError`
5. Catch other decryption errors → `CorruptedVaultError`

### CLI Error Handling
Updated `load_vault()` function to catch specific exceptions and display appropriate messages.

## Test Coverage
Added 6 new comprehensive tests:
- ✅ `test_encrypted_repository_wrong_password` - Incorrect password scenario
- ✅ `test_encrypted_repository_corrupted_ciphertext` - Corrupted ciphertext detection
- ✅ `test_encrypted_repository_success_with_correct_password` - Successful decryption
- ✅ `test_encrypted_repository_incorrect_password_vs_corrupted` - Side-by-side comparison
- ✅ `test_corrupted_vault_missing_fields` - Missing required fields
- ✅ `test_corrupted_vault_invalid_base64` - Invalid base64 encoding

Updated existing tests to expect new error messages.

**Test Results**: 61/61 tests passing ✅

## User Experience Before/After

### Before
```
$ localpass list vault.enc
Enter master password: wrong_password
Error: Invalid password or corrupted vault
❓ Is it my fault or the file's fault?
```

### After
```
# Scenario 1: Wrong password
$ localpass list vault.enc
Enter master password: wrong_password
Error: Incorrect master password.
✅ Clear instruction: re-enter password

# Scenario 2: Corrupted vault
$ localpass list vault.enc
Enter master password: correct_password
Error: Vault file is corrupted or unreadable.
✅ Clear instruction: restore from backup
```

## Backward Compatibility
- ✅ Both new exceptions inherit from `ValueError`
- ✅ Existing error handlers still work
- ✅ No breaking changes to APIs

## Files Changed
- `src/localpass/vault/repository.py` - Core implementation
- `src/localpass/cli.py` - Error message handling
- `tests/test_vault_crypto.py` - 6 new tests + updates
- `tests/test_cli.py` - 4 test updates

## References
- Closes: Issue #18
- Uses: `cryptography.hazmat.primitives.ciphers.aead.AESGCM` for authentication tag verification
