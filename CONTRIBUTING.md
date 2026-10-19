# Contributing to Inveil

Thank you for helping. This guide covers setup, tests, how to add a detector, and what a good pull request looks like. By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). Contributions are accepted under the project's [Apache-2.0 licence](LICENSE).

To report a vulnerability, do not open an issue; follow [SECURITY.md](SECURITY.md).

## Ways to help

- Report bugs and false positives or false negatives with a minimal, synthetic example. Never paste real personal data, keys or tokens.
- Pick up an issue labelled `good first issue` or `help wanted`.
- Improve the docs: wrong or missing instructions count as bugs.
- Open an issue before starting anything large (a new detector type, a contract change, a platform feature) so the approach can be agreed first.

## Development setup

Install the Rust toolchain with [rustup](https://rustup.rs). The exact toolchain used for releases and the components are in [`rust-toolchain.toml`](rust-toolchain.toml); `rustup` selects them for you. The minimum supported Rust version (1.89, `rust-version` in the workspace `Cargo.toml`) is checked separately by CI.

| OS | Extra requirements |
|---|---|
| macOS | Xcode command line tools (`xcode-select --install`). |
| Linux | `libdbus-1-dev` and `pkg-config` (the keychain backend), for example `sudo apt-get install libdbus-1-dev pkg-config`. |
| Windows | Visual Studio Build Tools with the C++ workload. |

```sh
git clone https://github.com/sansjack/inveil-app
cd inveil-app
cargo build
```

## Running checks

Run these before you open a pull request. CI runs them on Linux, macOS and Windows.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --no-default-features      # HTTP/2 off
```

Optional and slower:

```sh
cargo test --workspace -- --ignored   # end-to-end tests; install into a temporary HOME
cargo bench                           # criterion benchmarks (scan throughput)
cargo llvm-cov --workspace            # coverage, needs cargo-llvm-cov
cd crates/engine && cargo fuzz run <target>   # fuzzing, needs cargo-fuzz and a nightly toolchain
```

Tests that only apply to one operating system sit behind `#[cfg(target_os = "...")]`. If you change platform code (`crates/inveil/src/platform`), say in the pull request which operating systems you ran it on; CI covers the rest. Functions that generate service files, scripts or command lines are pure and tested on every OS, so keep new ones that way.

## Repository layout

| Path | What lives there |
|---|---|
| `crates/contract` | Wire types shared with backends. Pure data. |
| `crates/engine` | Scanning, detectors, policy, signature verification. No network, disk or OS calls. |
| `crates/inveil` | The binary: CLI, config, proxies, adapters, platform layer, updater. |
| `contract/v1` | OpenAPI, generated JSON Schema and test vectors. |
| `docs` | Documentation. Start at [ARCHITECTURE.md](docs/ARCHITECTURE.md). |

## Adding a detector

Detectors live in `crates/engine`. Pick the smallest option that works.

1. A new rule only (a new regex): no code. Rules are data in the signed snapshot. Add the rule to your policy file or to the example rules, and add a test with synthetic matching and non-matching input.
2. A new checksum validator (like Luhn or IBAN), so a regex match is only a finding when the value is structurally valid:
   - Add the function in [`crates/engine/src/validators.rs`](crates/engine/src/validators.rs) and return it from `check_for`.
   - Add a variant to `Validator` in [`crates/contract/src/snapshot.rs`](crates/contract/src/snapshot.rs). Clients reject unknown values, so this is a contract change: it must be additive, documented in [docs/CONTRACT.md](docs/CONTRACT.md) and `contract/v1/openapi.yaml`, and a backend must not send it to older clients.
   - Test valid, invalid and edge inputs.
3. A new kind of detector (for example one that is not regex based): implement the `Detector` trait in [`crates/engine/src/detector.rs`](crates/engine/src/detector.rs) (`detect`, and `redact` if it can rewrite text) in a new module, and register it where the `Scanner` is built in [`crates/engine/src/scan.rs`](crates/engine/src/scan.rs).

Rules for every detector:

- Use only synthetic test data. No real card numbers, ids or people.
- Findings carry a rule id and a salted hash, never the matched text. Do not log or return content.
- Think about performance: add a case to the benchmark if the detector runs on every request.
- Say what it will miss and where false positives are likely.

## Changing the contract

Anything in `crates/contract` is a public interface. Changes must be additive within v1, or propose `v2`. Update the Rust types, `contract/v1/openapi.yaml`, the generated schemas, the vectors and [docs/CONTRACT.md](docs/CONTRACT.md) in the same pull request. Regenerate the schemas with `UPDATE_SCHEMAS=1 cargo test -p contract schema` and the vectors with `UPDATE_VECTORS=1 cargo test -p engine --test vectors`. CI fails if either drifts from the types.

## Code style

- Idiomatic, readable Rust. Small functions with one job, guard clauses and early returns instead of deep nesting.
- Typed errors with `thiserror`. No `unwrap`, `expect` or `panic!` in non-test code; the workspace lints warn on them. Fail early with a clear message.
- Named constants instead of magic numbers.
- Typed structs and enums instead of loose maps or tuples.
- Comments explain why, not what. No commented-out code, no `TODO` comments (open an issue instead), no dead code.
- Brand strings go in [`crates/inveil/src/brand.rs`](crates/inveil/src/brand.rs).
- Any code that builds a command line or script from data passes the data as arguments, never by string interpolation.
- Do not add a dependency unless it is clearly needed; justify any new one in the pull request. `cargo deny` checks licences and advisories.
- Never log request content, tokens or keys. Debug and trace output is metadata only.

Format with `cargo fmt`; do not hand-format.

## Commits and pull requests

- One logical change per pull request, kept small enough to review.
- Commit subject in the imperative, at most 72 characters, optionally prefixed with `fix:`, `feat:`, `docs:`, `test:`, `refactor:` or `chore:`. Explain the why in the body when it is not obvious.
- Fill in the pull request template. Link the issue. Describe risks, especially for security, platform and contract changes.
- Add or update tests for behaviour changes and a `CHANGELOG.md` entry under "Unreleased".
- Changes to signing, verification, the updater, the install scripts or the contract need review from a maintainer (see [`.github/CODEOWNERS`](.github/CODEOWNERS)).
- Be patient and kind in review. Maintainers may ask for changes or decline a change that does not fit the project; see [GOVERNANCE.md](GOVERNANCE.md).

## Getting help

See [SUPPORT.md](SUPPORT.md).
