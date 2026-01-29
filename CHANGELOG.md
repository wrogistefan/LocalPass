# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] – 2026‑01‑29

### Added

- **JSON output mode**: New `--json` global flag for machine-readable output
  - Consistent JSON structure with `status`, `version`, `action`, and `data` fields
  - Non-interactive behavior in JSON mode (cannot prompt for passwords)
  - Enables scripting and automation use cases
- **Non-interactive automation mode**: New `--yes` / `-y` flags for write operations
  - Skips all confirmation prompts (weak password, overwrite, etc.)
  - Automatically confirms operations when used with `--json`
- **Password strength feedback improvements**:
  - Uses zxcvbn library with labeled strength levels (Very Weak → Very Strong)
  - Displays password strength warnings from zxcvbn analysis
  - Shows improvement suggestions for weak passwords
  - Prompts for confirmation when using weak passwords
- **New HIBP JSON responses**: HIBP check results now include structured data
  - `breached` boolean and `count` of breaches in JSON mode
- **New confirmation messages**: Consistent confirmation prompts for write operations

### Changed

- **Unified error handling**: All errors now use `click.ClickException`
  - Removed manual "Error:" prefixes - Click handles error formatting
  - Consistent error format in both human and JSON modes
- **Improved CLI output consistency**:
  - Success messages follow consistent patterns across commands
  - Confirmation prompts use consistent wording
- **Python version requirement**: Now requires Python 3.11+ (was 3.10)

### Fixed

- **Inconsistent version reporting**: Version now correctly reflects pyproject.toml
- **Double "Error:" prefix issues**: Errors no longer display redundant prefixes
  - ClickException handles error formatting correctly

### Notes

This release adds extensive automation capabilities for scripting and CI/CD pipelines while maintaining the security-first offline philosophy. The JSON output and `--yes` flags enable programmatic vault management without user interaction.

---

## [0.2.1] – 2026‑01‑26
### Fixed
- Corrected the README *Tests* badge to reference the `ci.yml` workflow
- Moved the Codecov badge into the main header for improved visual consistency
- Minor documentation cleanup and formatting improvements

### Notes
This is a maintenance release focused solely on documentation and metadata polish.
No changes were made to the vault format, CLI commands, cryptographic model, or application behavior.

---

## [0.2.0] – 2026‑01‑25

### Added

- Complete offline‑first vault architecture using Argon2id + AES‑256‑GCM
- Manual HIBP password check (`hibp-check`) using k‑anonymity (SHA‑1 prefix only)
- Full security documentation (`docs/SECURITY.md`)
- Comprehensive User Manual (`docs/USER_MANUAL.md`)
- Professional README header with project badges
- Verified cross‑platform support (Windows, macOS, Linux/WSL)
- 99% test coverage across the codebase

### Changed

- Improved README structure and feature descriptions
- Refined documentation for clarity and consistency

### Notes

This is the first stable and fully documented release of LocalPass, establishing the foundation for all future versions.

## [0.1.3] - 2026-01-20

### Added

- **Password confirmation**: Master password must be confirmed during vault initialization
- **Required field validation**: Service, username, and password fields are now required and cannot be empty during entry addition
- **Password confirmation for entries**: Passwords must be confirmed when adding new entries
- **Improved user prompts**: Enhanced CLI prompts with better error messages and validation

### Changed

- Improved user experience with mandatory field validation and password confirmation prompts
- Better error handling for empty required fields
- `prompt_required_field` now uses Click helpers for consistent cancellation behavior and normalizes prompt text to handle colons gracefully

## [0.1.2] - 2026-01-20

### Added

- **Short numeric ID support**: Users can now specify short numeric IDs (1, 2, 3, etc.) when adding entries instead of relying solely on auto-generated IDs
- **Custom ID handling**: Vault service now handles mixed auto-generated and custom IDs with intelligent next_id tracking
- **Enhanced ID validation**: Better handling of edge cases with custom IDs

### Changed

- ID assignment logic improved for better user experience with manual ID entry
- next_id deserialization now handles missing, invalid, and edge case values gracefully

## [0.1.1] - 2026-01-18

### Added

- Improved serialization robustness with missing optional field defaults
- Enhanced timestamp validation for vault data integrity
- Better error handling for corrupted files
- Repository safety warnings for plaintext usage
- Vault API enhancement: `remove_entry_by_id` method

### Changed

- Error handling improved for invalid vaults
- Test coverage increased to >95%

## [0.1.0] - 2026-01-13

### Added

- Complete LocalPass CLI with commands: `init`, `add`, `list`, `show`, `remove`
- Encrypted vault implementation using Argon2id + AES-GCM
- Vault serialization and deserialization
- Domain models for vault entries
- Repository pattern for vault storage
- Service layer for business logic
- Comprehensive test suite for crypto and CLI functionality
- CI/CD pipeline with GitHub Actions
- Code quality tools: Ruff, Black, Mypy
- Pre-commit hooks for automated code formatting

### Security

- Argon2id key derivation with memory-hard parameters (102,400 KiB, 2 iterations, 8 lanes)
- AES-256-GCM authenticated encryption
- Random salt and nonce generation for each vault
- Secure password handling with getpass

### Changed

- Project structure reorganized for PyPI compliance
- Improved error handling throughout the codebase
- Enhanced CLI user experience with clear prompts and feedback

### Fixed

- Various bugs in vault serialization
- Edge cases in cryptographic operations
- CLI argument parsing issues

[0.3.0]: https://github.com/wrogistefan/LocalPass/releases/tag/v0.3.0
[0.2.1]: https://github.com/wrogistefan/LocalPass/releases/tag/v0.2.1
[0.2.0]: https://github.com/wrogistefan/LocalPass/releases/tag/v0.2.0
[0.1.3]: https://github.com/wrogistefan/LocalPass/releases/tag/v0.1.3
[0.1.2]: https://github.com/wrogistefan/LocalPass/releases/tag/v0.1.2
[0.1.1]: https://github.com/wrogistefan/LocalPass/releases/tag/v0.1.1
[0.1.0]: https://github.com/wrogistefan/LocalPass/releases/tag/v0.1.0