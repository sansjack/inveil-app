# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0, minor versions may contain breaking changes to configuration, the CLI and the backend contract; they are called out under "Changed" or "Removed".

## [Unreleased]

### Added

- Local proxy for AI tools: an API proxy on localhost and a browser proxy, scanning chat requests and blocking, redacting or logging findings.
- Backend contract v1: signed rules snapshots (`GET /v1/rules`), optional usage batches (`POST /v1/usage`) and enrollment (`POST /v1/enroll`), with Rust types in `crates/contract` and an OpenAPI description.
- Ed25519 signing with separate domains for policy, update and delegation, verified before parsing; monotonic versions, expiry and audience checks.
- Layered configuration (flags, `INVEIL_*` environment, `inveil.toml`, defaults) with standalone, managed and offline modes, and server-enforced settings that local configuration can only tighten.
- `inveil keygen`, `inveil sign` and `inveil verify`.
- Signed, verified self-update with rollback (`update.mode`: `off`, `notify`, `download`, `install`).
- Install script for macOS and Linux with checksum and manifest verification and optional enrollment.
- macOS, Windows and Linux support.
- Documentation, community files and release pipeline with SBOM, checksums and build provenance.

[Unreleased]: https://github.com/sansjack/inveil-app/commits/main
