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

## Provider checks

Providers change things silently, and a broken signal in `crates/inveil/src/builtin_signals.json` can make a usage event wrong. Three layers watch for that.

- **Fixtures** (run by `cargo test --workspace`). Each file in `crates/inveil/tests/provider_fixtures/` is one sanitised exchange: the request (fake credentials only), the provider's response (JSON or SSE) and the event we expect. `proxy/provider_tests.rs` runs every file through the real signals table and usage tap, and through the real localhost proxy in front of a fake upstream, which must hand the client the same status, headers and bytes. Run just these with `cargo test -p inveil --bin inveil provider_tests`. Files named `drift-*` are provider changes (renamed field, moved path, other content type, empty or garbled body) that must fall back to `unknown` or zero. A response fixture may set `compression` (`gzip`, `deflate`, `br`, `zstd`), `truncate_bytes` and `leading_newlines` (an over-budget stream); the bytes the caller receives must still equal the upstream's.

  What the usage tap reads, always as the provider reports it and never priced: `input_tokens` is the whole prompt including cached tokens, `cache_read_tokens` and `cache_write_tokens` are subsets of it, and `output_tokens` is everything billed as output including thinking and reasoning.
  - Anthropic: `input_tokens` plus cache read and cache creation tokens make the prompt; `output_tokens` as is.
  - OpenAI Responses: `input_tokens`, `input_tokens_details.cached_tokens`, `output_tokens` (reasoning is inside it).
  - Chat Completions (OpenAI, OpenRouter, Copilot, LiteLLM and other compatible gateways): `prompt_tokens`, `prompt_tokens_details.cached_tokens`, `completion_tokens` (`reasoning_tokens` is already inside it, so it is not added). A stream carries usage only in the final chunk and only when the request sets `stream_options.include_usage` (OpenRouter always sends it); without it tokens stay 0. SSE comment lines such as `: OPENROUTER PROCESSING` are skipped.
  - Gemini (API, Vertex, and Code Assist's `response.usageMetadata`): `promptTokenCount` (already includes cached tokens), `cachedContentTokenCount`, and `candidatesTokenCount + thoughtsTokenCount` as output. `toolUsePromptTokenCount` is ignored because the docs do not say how it is billed. Streamed values are cumulative, so each counter keeps its maximum.
  - Compressed responses (`gzip`, `deflate` as zlib, `br`, `zstd`) are decoded from a copy of the bytes as they stream past, and decoding stops after 32 MiB of output. Stacked encodings and raw deflate are not decoded and count as 0 tokens.
- **Canary** (every 6 hours in `.github/workflows/provider-canary.yml`). Sends one tiny real request per provider, streaming and not, through the real client and checks the answer arrived intact and the event is right. Locally: `ANTHROPIC_API_KEY=... OPENAI_API_KEY=... GEMINI_API_KEY=... cargo test -p inveil --test canary -- --ignored canary_ --nocapture`. A provider without its key is reported `skipped`. Models come from `CANARY_ANTHROPIC_MODEL`, `CANARY_OPENAI_MODEL`, `CANARY_GEMINI_MODEL` and `CANARY_OPENROUTER_MODEL`. Every provider must report tokens above 0. OpenRouter is routed through a catalog entry that exists only in the canary, so the shipped client does not intercept it. `CANARY_RESULTS=path` writes the JSON summary to a file instead of stdout.
- **Evidence watch**. A signal may carry `evidence_url` (https) and `evidence_contains`: a public page and a string it must still contain. Add them only when you fetched the page and saw the string. `cargo test -p inveil --test canary -- --ignored evidence_watch` fetches each one.

**Adding a signal.** Add a fixture that exercises it and list the signal id in the fixture's `covers`. A test fails if a signal with `"verified": true` has no fixture, or if a fixture claims a signal its expected event does not show. Copy the nearest existing file, keep credentials obviously fake, and add a `drift-*` file when the signal reads a specific path or field.

**Reading an alert.** The Discord embed lists each failed check as `provider: detail`, and skipped providers in their own field (a missing repository secret shows up there). `HTTP 401` or `400` is usually the key; `HTTP 404` on the model is a retired model id (override it with the variable above); `billing_signal`, `model_signal` or `tokens` problems mean the provider changed what we read, so capture one real exchange, update the fixture and the signal. An `evidence:<signal id>` failure means the cited page changed: re-read it before touching the signal.

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
