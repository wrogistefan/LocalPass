# LocalPass v0.1.0 Release Notes

## 🎉 Summary

LocalPass v0.1.0 is the first public release of our local-first, offline password manager. This release introduces a complete CLI-based password management system with strong encryption and zero cloud dependencies.

## 🌟 Highlights

### Core Features

- **🔒 Secure Vault**: Argon2id + AES-GCM encryption for maximum security
- **📦 CLI Interface**: Full command-line interface for vault management
- **💻 Cross-platform**: Works on Windows, macOS, and Linux
- **📖 Open Source**: Fully transparent codebase under Apache License 2.0

### CLI Commands

- `localpass init <path>` - Initialize a new encrypted vault
- `localpass add <path>` - Add new entries to your vault
- `localpass list <path>` - List all entries in your vault
- `localpass show <path> <id>` - Show detailed entry information
- `localpass remove <path> <id>` - Remove entries from your vault

## 📥 Installation

### Using pip

```bash
pip install localpass
```

### From source

```bash
git clone https://github.com/wrogistefan/LocalPass.git
cd LocalPass
pip install -e .
```

## 🔐 Security Features

- **Argon2id** key derivation with memory-hard parameters
- **AES-256-GCM** authenticated encryption
- **Random salt and nonce** for each vault
- **Zero telemetry** and no cloud dependencies

## 📚 Documentation

Comprehensive documentation is included in this release:

- [📖 User Manual](docs/USER_MANUAL.md) - Complete CLI usage guide
- [🔐 Security Documentation](docs/SECURITY.md) - Threat model and encryption details
- [📜 Changelog](CHANGELOG.md) - Full release history

## ⚠️ Breaking Changes

None for v0.1.0 - this is the initial release.

## 🐛 Known Issues

- No GUI interface (CLI only)
- No mobile support
- No import/export functionality
- No password recovery mechanism

## 🚀 Upgrade Notes

This is the first public release, so no upgrade path is needed.

## 📋 Future Roadmap

- GUI interface
- Mobile support
- Import/export functionality
- Browser integration
- Multi-factor authentication

## 🤝 Contributing

Contributions are welcome! Please see the GitHub repository for contribution guidelines.

## 📄 License

LocalPass is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

Thank you to all contributors, testers, and early adopters who helped make this release possible!

## 📬 Contact

For questions, issues, or feedback:
- GitHub: https://github.com/wrogistefan/LocalPass
- Email: lukasz.perek@outlook.com