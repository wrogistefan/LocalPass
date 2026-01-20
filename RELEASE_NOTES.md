# LocalPass v0.1.3 Release Notes

## 🎉 Summary

LocalPass v0.1.3 enhances user experience with improved input validation and password confirmation prompts. This release adds mandatory field validation and password confirmation to prevent errors and improve security during vault operations.

## 🌟 Highlights

### New Features

- **Password Confirmation**: Master password must be confirmed during vault initialization, and entry passwords must be confirmed when adding entries
- **Required Field Validation**: Service, username, and password fields are now mandatory and cannot be left empty
- **Enhanced User Prompts**: Improved CLI prompts with better error messages and validation for a smoother user experience

### Example Usage

```bash
# Initialize vault with password confirmation
localpass init myvault.lp

# Add entry with required field validation and password confirmation
localpass add myvault.lp

# Add entry with custom numeric ID
localpass add myvault.lp --id 1
```

## 📥 Installation

### Using pip

```bash
pip install localpass==0.1.3
```

### From source

```bash
git clone https://github.com/wrogistefan/LocalPass.git
cd LocalPass
git checkout v0.1.3
pip install -e .
```

## 🔐 Security Features

- **Argon2id** key derivation with memory-hard parameters
- **AES-256-GCM** authenticated encryption
- **Random salt and nonce** for each vault
- **Zero telemetry** and no cloud dependencies

## ✨ What's Changed

### Added
- Password confirmation prompts for vault initialization and entry addition
- Required field validation for service, username, and password fields
- Enhanced user input prompts with better error handling
- Improved CLI user experience with mandatory validation

### Changed
- Vault initialization now requires password confirmation
- Entry addition now validates all required fields and confirms passwords
- Better error messages for invalid or empty inputs

### Technical Details
- New prompt functions for required fields and password confirmation
- Enhanced input validation prevents empty or invalid entries
- Backward compatible with existing vaults (no data format changes)

## 📚 Documentation

Comprehensive documentation is included in this release:

- [📖 User Manual](docs/USER_MANUAL.md) - Complete CLI usage guide
- [🔐 Security Documentation](docs/SECURITY.md) - Threat model and encryption details
- [📜 Changelog](CHANGELOG.md) - Full release history

## ⚠️ Breaking Changes

None for v0.1.3 - fully backward compatible with previous versions. Existing vaults work without any changes.

## 🐛 Known Issues

- No GUI interface (CLI only)
- No mobile support
- No import/export functionality
- No password recovery mechanism

## 📈 Upgrade Notes

Existing vaults from v0.1.2 and earlier are fully compatible. The new validation features only affect user input during vault operations, not stored data.

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