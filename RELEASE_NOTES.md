# LocalPass v0.1.2 Release Notes

## 🎉 Summary

LocalPass v0.1.2 introduces support for short custom numeric IDs, giving users more flexibility in managing their password vault entries. This release improves ID handling and maintains full backward compatibility with existing vaults.

## 🌟 Highlights

### New Features

- **Short Numeric IDs**: Specify custom numeric IDs (1, 2, 3, etc.) when adding entries with the `--id` option
- **Intelligent ID Tracking**: The vault now smartly tracks `next_id` to avoid conflicts between auto-generated and custom IDs
- **Enhanced ID Validation**: Robust handling of edge cases when deserializing vault files

### Example Usage

```bash
# Add entry with auto-generated ID (default)
localpass add myvault.lp

# Add entry with custom numeric ID
localpass add myvault.lp --id 1
```

## 📥 Installation

### Using pip

```bash
pip install localpass==0.1.2
```

### From source

```bash
git clone https://github.com/wrogistefan/LocalPass.git
cd LocalPass
git checkout v0.1.2
pip install -e .
```

## 🔐 Security Features

- **Argon2id** key derivation with memory-hard parameters
- **AES-256-GCM** authenticated encryption
- **Random salt and nonce** for each vault
- **Zero telemetry** and no cloud dependencies

## ✨ What's Changed

### Added
- Support for short numeric custom IDs via `--id` option
- Intelligent next_id computation considering both auto-generated and custom IDs
- Comprehensive tests for ID handling edge cases

### Fixed
- next_id deserialization now handles missing, invalid, and edge case values
- Better validation when mixing custom and auto-generated IDs

### Technical Details
- Mixed auto-generated and custom IDs now work seamlessly
- next_id correctly computes based on max existing numeric IDs
- Backward compatible with existing vaults

## 📚 Documentation

Comprehensive documentation is included in this release:

- [📖 User Manual](docs/USER_MANUAL.md) - Complete CLI usage guide
- [🔐 Security Documentation](docs/SECURITY.md) - Threat model and encryption details
- [📜 Changelog](CHANGELOG.md) - Full release history

## ⚠️ Breaking Changes

None for v0.1.2 - fully backward compatible with v0.1.1 vaults.

## 🐛 Known Issues

- No GUI interface (CLI only)
- No mobile support
- No import/export functionality
- No password recovery mechanism

## 📈 Upgrade Notes

Existing vaults from v0.1.1 are fully compatible and can continue to use auto-generated IDs, or optionally use custom numeric IDs going forward.

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