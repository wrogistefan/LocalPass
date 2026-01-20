# Issue #18: Distinguish between Incorrect Password and Corrupted Vault

## Summary
Implemented a comprehensive error handling mechanism to differentiate between two distinct failure modes during vault decryption:
- **Incorrect Master Password**: User enters wrong password, but vault file is intact
- **Corrupted Vault File**: Vault file is damaged, truncated, or malformed

Previously, both scenarios raised a generic "Invalid password or corrupted vault" error, making it impossible for users to understand what went wrong and difficult for developers to diagnose issues.

## Changes Made

### 1. New Exception Classes
**File:** [src/localpass/vault/repository.py](src/localpass/vault/repository.py)

Added two custom exception classes that inherit from `ValueError`:
- `IncorrectPasswordError`: Raised when decryption fails due to authentication tag mismatch (wrong password)
- `CorruptedVaultError`: Raised when vault structure is invalid, files are missing/malformed, or JSON parsing fails

```python
class IncorrectPasswordError(ValueError):
    """Raised when the master password is incorrect."""
    pass

class CorruptedVaultError(ValueError):
    """Raised when the vault file is corrupted or unreadable."""
    pass
```

### 2. Enhanced Decryption Logic
**File:** [src/localpass/vault/repository.py](src/localpass/vault/repository.py) - `EncryptedVaultRepository.load()`

Refactored the decryption logic to distinguish between error types:

- **JSON Parsing Errors** → `CorruptedVaultError` (file syntax or structure issues)
- **Missing Required Fields** → `CorruptedVaultError` (incomplete vault data)
- **Invalid Base64 Encoding** → `CorruptedVaultError` (corrupted binary fields)
- **InvalidTag Exception** → `IncorrectPasswordError` (authentication failure = wrong password)
- **Other Decryption Errors** → `CorruptedVaultError` (file corruption)
- **Decrypted JSON Parsing** → `CorruptedVaultError` (plaintext is invalid)

### 3. Plaintext Repository Updates
**File:** [src/localpass/vault/repository.py](src/localpass/vault/repository.py) - `PlaintextVaultRepository.load()`

Updated plaintext repository to also raise `CorruptedVaultError` for JSON parsing failures, ensuring consistency across repository implementations.

### 4. CLI Error Handling
**File:** [src/localpass/cli.py](src/localpass/cli.py) - `load_vault()` function

Added specific exception handling to catch and display user-friendly error messages:

```python
def load_vault(path: str, password: str) -> ...:
    repo, service = get_vault_service()
    try:
        vault = service.load_vault(path, password)
        return repo, service, vault
    except IncorrectPasswordError:
        raise click.ClickException("Error: Incorrect master password.")
    except CorruptedVaultError:
        raise click.ClickException("Error: Vault file is corrupted or unreadable.")
    except ValueError as e:
        raise click.ClickException(f"Error: {e}")
```

### 5. Comprehensive Test Coverage
**File:** [tests/test_vault_crypto.py](tests/test_vault_crypto.py)

Added 6 new test cases covering:
1. **Incorrect Password Scenario** (`test_encrypted_repository_wrong_password`)
   - Verifies `IncorrectPasswordError` is raised with correct message
   
2. **Corrupted Ciphertext Scenario** (`test_encrypted_repository_corrupted_ciphertext`)
   - Simulates truncated ciphertext (binary corruption)
   - Verifies `CorruptedVaultError` is raised
   
3. **Successful Decryption** (`test_encrypted_repository_success_with_correct_password`)
   - Validates that correct password still works as expected
   
4. **Missing Fields** (`test_corrupted_vault_missing_fields`)
   - Validates corruption detection for incomplete vault data
   
5. **Invalid Base64** (`test_corrupted_vault_invalid_base64`)
   - Validates corruption detection for malformed encoding
   
6. **Incorrect Password vs Corrupted Comparison** (`test_encrypted_repository_incorrect_password_vs_corrupted`)
   - Comprehensive test showing both exception types are properly distinct

Updated 4 existing CLI tests to expect the new error messages:
- `test_add_with_wrong_master_password`
- `test_list_with_wrong_master_password`
- `test_show_with_wrong_master_password`
- `test_remove_with_wrong_master_password`

Updated existing vault crypto tests to use new exception types:
- `test_plaintext_repository_invalid_json`
- `test_encrypted_repository_invalid_json`
- `test_encrypted_repository_missing_fields`
- `test_encrypted_repository_invalid_decrypted_json`

## User Experience Improvements

### Before
```
Error: Invalid password or corrupted vault
(User confused: is it their mistake or a file problem?)
```

### After
```
# Scenario 1: Wrong password
Error: Incorrect master password.
(Clear: user needs to re-enter password correctly)

# Scenario 2: Corrupted vault
Error: Vault file is corrupted or unreadable.
(Clear: user needs to restore from backup or recover the file)
```

## Technical Details

### How Password Validation Works
The `cryptography` library's `AESGCM` cipher uses an authentication tag (Galois/Counter Mode) that is verified during decryption. If the password is incorrect, the derived key will be wrong, and the authentication tag verification will fail, raising `InvalidTag` exception. This is the most reliable way to detect password mismatch without trying to decrypt dummy data.

### How Corruption Detection Works
Vault corruption can manifest in several ways:
1. **JSON Format Error**: File truncated or mangled → `json.JSONDecodeError`
2. **Missing Fields**: Required encryption parameters missing → `KeyError`
3. **Base64 Decode Error**: Binary fields malformed → `binascii.Error`
4. **Decrypted Data Invalid**: Plaintext doesn't decode to valid JSON → `json.JSONDecodeError`

All these scenarios are now properly caught and reported as `CorruptedVaultError`.

## Test Results
```
61 passed in 13.04s
```

All tests pass, including:
- 23 vault crypto tests (including 6 new tests for Issue #18)
- 35 CLI tests
- 3 vault model tests

## Backward Compatibility
- Exception types inherit from `ValueError`, so existing code catching `ValueError` still works
- Custom code specifically catching these exceptions will now properly handle both cases
- Error messages are clear and actionable

## Files Modified
1. `src/localpass/vault/repository.py` - Core implementation
2. `src/localpass/cli.py` - Error handling and user messaging
3. `tests/test_vault_crypto.py` - New and updated tests
4. `tests/test_cli.py` - Updated test expectations

## Summary
This implementation provides users with clear, actionable error messages that distinguish between user error (wrong password) and system issues (corrupted vault), improving the debugging experience and overall usability of the LocalPass CLI.
