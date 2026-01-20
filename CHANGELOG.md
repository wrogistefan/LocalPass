# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.2]: https://github.com/wrogistefan/LocalPass/releases/tag/v0.1.2
[0.1.1]: https://github.com/wrogistefan/LocalPass/releases/tag/v0.1.1
[0.1.0]: https://github.com/wrogistefan/LocalPass/releases/tag/v0.1.0