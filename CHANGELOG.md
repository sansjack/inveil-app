# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0, minor versions may contain breaking changes to configuration, the CLI and the backend contract; they are called out under "Changed" or "Removed".

## [Unreleased]

### Changed

- Releases are co-signed and published from CI: the second update key signs in its own `release-manifest-cosigning` environment (`cosign-manifest`), `publish` waits for approval in `release-publish` after every install test passed, and `Verify published release` runs automatically, turning the release back into a draft if it fails. No offline co-signing step. See docs/RELEASING.md and THREAT_MODEL.md R3.

## [0.2.0] - 2026-10-19

### Fixed

- A `mode = "managed"` set in the per-user file or `INVEIL_MODE` no longer re-enables local `dry_run` or refuses a local `open` failure mode on an enrolled device: only a system-wide file declaring `managed` counts as system-managed (`Config::system_managed`), so the enrolled rules apply and the ignored keys are warned about.
- An enrolled device's `file` usage sink no longer uploads events to the backend: only `usage.sink = "http"` opts in under `usage_reporting = "optional"`; `file` or `none` send heartbeats only.

### Added

- Team devices: a client enrolled through an invite (`auth.mode = "enrolled"`) with a `backend.url` now follows the organisation's signed settings like a managed one, except that it starts on the built-in rules before its first fetch (`Config::owned_by_backend`). Local `dry_run` and `open` failure modes are ignored with a startup warning rather than refused; local `offline` is ignored unless the signed settings allow it. Trust anchors stay local.
- Usage heartbeats for backend-owned clients: under `usage_reporting = "optional"` an enrolled or managed client sends heartbeats with no events (and events too if its local sink is on; on an enrolled device only the `http` sink counts); `disabled` sends nothing.
- `inveil refetch` restarts the background service to fetch the organisation's rules now and prints the policy version it is running. It refuses only when the device has no `backend.url`.
- `GET /health` includes `policy_version`.
- Local proxy for AI tools: an API proxy on localhost and a browser proxy, scanning chat requests and blocking, redacting or logging findings.
- Backend contract v1: signed rules snapshots (`GET /v1/rules`), optional usage batches (`POST /v1/usage`) and enrollment (`POST /v1/enroll`), with Rust types in `crates/contract` and an OpenAPI description.
- Ed25519 signing with separate domains for policy, update and delegation, verified before parsing; monotonic versions, expiry and audience checks.
- Layered configuration (flags, `INVEIL_*` environment, `inveil.toml`, defaults) with standalone, managed and offline modes, and server-enforced settings that local configuration can only tighten.
- `inveil keygen`, `inveil sign` and `inveil verify`.
- Signed, verified self-update with rollback (`update.mode`: `off`, `notify`, `download`, `install`).
- Install script for macOS and Linux with checksum and manifest verification and optional enrollment.
- macOS, Windows and Linux support.
- Documentation, community files and release pipeline with SBOM, checksums and build provenance.

[Unreleased]: https://github.com/sansjack/inveil-app/compare/v0.2.0...main
[0.2.0]: https://github.com/sansjack/inveil-app/releases/tag/v0.2.0
