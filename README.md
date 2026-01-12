# LocalPass

[![codecov](https://codecov.io/gh/lukas/LocalPass/branch/main/graph/badge.svg)](https://codecov.io/gh/lukas/LocalPass)

LocalPass is a minimal, offline password manager designed for local-first usage. It stores your vault exclusively on your device, with no cloud integration, telemetry, or user accounts. The project emphasizes transparency, simplicity, and security through open-source development.

## Security Notice

**WARNING: This project is in pre-release / early development stage.**

- **Do not use LocalPass to store real passwords.** It is not secure and may expose your credentials to risks.
- No security guarantees are provided at this time. The code and cryptography implementations are subject to change.
- No security audit has been conducted.
- Use at your own risk. This software is experimental and intended for testing and development purposes only.

## Features

- **Offline Storage**: Vault stored locally on your device only.
- **No Cloud Dependency**: Zero integration with external services.
- **Open-Source**: Fully transparent codebase.
- **Minimal Design**: Focus on simplicity and clarity.
- **Public Vault Format**: Vault format will be publicly documented for interoperability.
- **Cryptography**: Planned use of Argon2id for key derivation and AES-256-GCM for encryption (currently placeholder).

## Philosophy

LocalPass adheres to the "local-first" philosophy, prioritizing user control, privacy, and offline functionality. By keeping everything local and open-source, we aim to provide a trustworthy alternative to cloud-based password managers.

## Roadmap

- [ ] Implement basic vault creation and password storage.
- [ ] Document vault format publicly.
- [ ] Integrate Argon2id + AES-256-GCM cryptography.
- [ ] Add CLI interface for management.
- [ ] Conduct security audit.
- [ ] Release stable version.

## Development

To set up pre-commit hooks for code quality:

```bash
pre-commit install
```

## Project Status

This project is in early development. Core functionality is not yet implemented. Contributions are welcome, but please review the security notice above.

## Security

Security is paramount. All cryptographic operations will follow best practices. The vault format is designed to be simple yet secure. For more details, see the [Security Documentation](security.md) (to be added).

## License

This project is licensed under the Apache License 2.0.  
See the [LICENSE](LICENSE) file for full details.

## Author

Created by **Łukasz Perek** — local‑first software enthusiast.
