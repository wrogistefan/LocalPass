# LocalPass v0.2.0 Release Notes

## 🎉 Summary

LocalPass v0.2.0 introduces an optional manual password breach check using the Have I Been Pwned (HIBP) k-anonymity API, along with documentation improvements and enhanced test coverage. This release maintains the offline-first philosophy while providing users with an additional security tool.

## 🌟 Highlights

### New Features

- **Manual HIBP Password Check**: New `localpass hibp-check` command for checking passwords against known breaches
- **Enhanced Documentation**: Updated README with Security Model section and improved structure
- **High Test Coverage**: Achieved 99% test coverage with comprehensive validation
- **Cross-Platform Compatibility**: Verified behavior on Windows PowerShell and Unix shells (WSL/bash)

### Example Usage

```bash
# Check a password against breaches
localpass hibp-check

# Initialize vault (unchanged)
localpass init myvault.lp

# Add entry with custom ID
localpass add myvault.lp --id 1
```

## 📥 Installation

### Using pip

```bash
pip install localpass==0.2.0
```

### From source

```bash
git clone https://github.com/wrogistefan/LocalPass.git
cd LocalPass
git checkout v0.2.0
pip install -e .
```

## 🔐 Security Features

- **Argon2id** key derivation with memory-hard parameters
- **AES-256-GCM** authenticated encryption
- **Random salt and nonce** for each vault
- **Zero telemetry** and no cloud dependencies
- **Manual HIBP check** with k-anonymity (only SHA-1 prefix sent)

## ✨ What's Changed

### Added

- Manual HIBP password check command with explicit user confirmation
- Security Model section in README
- Professional badges and improved documentation structure
- 99% test coverage achievement
- Cross-platform shell compatibility verification

### Changed

- Updated README with clearer feature descriptions
- Improved error handling for network operations

### Security

- Explicit confirmation before HIBP API requests
- Only first 5 characters of SHA-1 hash transmitted
- No automatic network calls

## 📚 Documentation

Comprehensive documentation is included in this release:

- [📖 User Manual](docs/USER_MANUAL.md) - Complete CLI usage guide including new HIBP command
- [🔐 Security Documentation](docs/SECURITY.md) - Threat model and encryption details
- [📜 Changelog](CHANGELOG.md) - Full release history

## ⚠️ Breaking Changes

None for v0.2.0 - fully backward compatible with previous versions. Existing vaults work without any changes.

## 🐛 Known Issues

- No GUI interface (CLI only)
- No mobile support
- No import/export functionality
- No password recovery mechanism

## 📈 Upgrade Notes

Existing vaults from v0.1.x are fully compatible. The new HIBP feature is optional and does not affect existing functionality.

## 🚀 Upgrade Steps

```bash
pip install --upgrade localpass
# Your existing vaults will work without any changes!
```

## 📋 Future Roadmap

- GUI interface
- Mobile support
- Import/export functionality
- Browser integration
- Multi-factor authentication
- Support for non-numeric custom IDs

## 🤝 Contributing

Contributions are welcome! Please see the GitHub repository for contribution guidelines.

## 📄 License

LocalPass is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

Thank you to all contributors, reviewers, and community members who helped improve this release!

## 📬 Contact

For questions, issues, or feedback:
- GitHub: https://github.com/wrogistefan/LocalPass
- Email: lukasz.perek@outlook.com