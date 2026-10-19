# Supported tools

What inveil covers, per tool in the default catalog (`examples/rules.json`), and what you have to do for each. `inveil doctor` checks the same things on your machine and prints Covered, Needs setup or Not covered for every enabled tool, with the reason.

- **Covered automatically**: `inveil install` (or `inveil browser-setup`) is the only step.
- **Covered with a setup step**: one more thing, named below, has to be done by you.
- **Not yet**: inveil cannot read this traffic today.

The Gemini and xAI routes (`gemini-web`, `gemini-cli`, `xai-api`) were added to the built-in catalog from public documentation and have not been verified against the real tools. Treat them as unconfirmed until `inveil doctor` and a test message agree, and use `inveil discover` to collect evidence if one does not work.

The catalog is signed and can change without a new release, so the table is a guide. `inveil doctor` reads the catalog you actually run.

## Local tools (pointed at the API proxy)

The tool talks plain HTTP to `127.0.0.1:<listen.port>`, so no CA is involved. The variable comes from `tools[].env_var` in the signed catalog. `inveil install` writes only from an allow-list, because the name comes from the catalog and ends up in a settings file: `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL` and `GOOGLE_GEMINI_BASE_URL`, plus a name the catalog chose that has the strict shape `NAME_BASE_URL` (capital letters, digits and single underscores) when the tool id is `claude-code`, `codex-api` or `gemini-cli`. Anything else, including `NODE_OPTIONS`, `LD_*`, `PATH`, `HOME` or a `_URL` name on an unknown tool, is refused. The installer writes the Claude Code settings file and `~/.gemini/.env` atomically with mode 0600 and refuses to write through a symlink.

| Tool | Status | What happens |
|---|---|---|
| Claude Code (`claude-code`) | Covered automatically | `inveil install` writes `ANTHROPIC_BASE_URL` to the `env` map of `~/.claude/settings.json`. `inveil install --managed` writes it to the machine-wide managed settings instead (see below). |
| Gemini CLI with an API key (`gemini-cli`) | Covered automatically | `inveil install` writes `GOOGLE_GEMINI_BASE_URL` to `~/.gemini/.env`. Gemini CLI documents that variable for API-key authentication only. |
| Gemini CLI with a Google login | Not yet | The base-URL variable is not documented for that sign-in, and its traffic is not routed through the proxy. |
| Codex with an OpenAI API key (`codex-api`) | Covered | `inveil install` sets `openai_base_url` in `$CODEX_HOME/config.toml` (default `~/.codex/config.toml`), editing it in place so comments and other keys are kept. A file that is not valid TOML is left alone and install fails with the reason. `inveil uninstall` removes the key only while it still points at the proxy. |
| xAI API (`xai-api`) | Not yet | The default catalog gives this tool no `env_var`, so there is nothing to set. Add one to your signed catalog if your SDK reads a base-URL variable. |

## Browser traffic (decrypted by the browser proxy)

These need `inveil browser-setup` once (it creates the CA, trusts it for your user and applies the proxy auto-config).

| Tool | Status | What happens |
|---|---|---|
| Claude, ChatGPT, Gemini and Grok in Chrome, Edge, Brave or Safari | Covered with a setup step | `inveil browser-setup`, then restart the browser. |
| The same sites in Firefox | Covered with a setup step | Firefox keeps its own certificate store. On Linux `browser-setup` imports the CA into existing profiles; on macOS and Windows set `security.enterprise_roots.enabled` to `true` in `about:config`. `inveil doctor` cannot check this and says so. |
| Codex signed in with ChatGPT (`codex`) | Covered with a setup step | Codex ignores the system proxy. Start it with `inveil run codex`, which sets `HTTPS_PROXY` and `CODEX_CA_CERTIFICATE` for that one process. |
| Cursor Agent CLI (`cursor`) | Covered with a setup step | Start it with `inveil run cursor-agent` (or your command). Its runtime is assumed to be Node.js and has not been verified; treat it as unconfirmed until `inveil doctor` and a test message agree. |
| ChatGPT desktop app | Not yet | The default catalog entry covers `chatgpt.com` in a browser. Whether the desktop app honours the system proxy and trusts the system store has not been verified, so it is not claimed. Use `inveil discover` to collect evidence. |
| Cursor desktop | Not yet | There is no catalog entry for the editor's own traffic. Use `inveil discover` to find its hosts and formats. |
| Apps that pin their certificates | Not covered, by design | A pinned app rejects the local CA, so inveil cannot read it. The proxy tunnels it untouched. See the [threat model](THREAT_MODEL.md). |

## Per-runtime CA trust

For tools run with `inveil run <command>`, the variables are chosen by the program's runtime and set for that process only. A global `SSL_CERT_FILE` would replace the roots of every other tool, so inveil never sets one globally.

| Runtime | Variables | Points at |
|---|---|---|
| Chrome, Edge, Brave, Safari | none | the operating system's store and proxy settings |
| Firefox | none | its own store (see above) |
| Node.js (`node`, `npm`, `npx`, `bun`) | `NODE_EXTRA_CA_CERTS` | the inveil CA, added to Node's roots |
| Codex | `CODEX_CA_CERTIFICATE` | the inveil CA |
| Python (`python`, `pip`, `uv`) | `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE` | `ca-bundle.pem`: system roots plus the inveil CA |
| Rust (`cargo`, `rustc`), Go | `SSL_CERT_FILE` | `ca-bundle.pem` |
| curl | `CURL_CA_BUNDLE` | `ca-bundle.pem` |
| git | `GIT_SSL_CAINFO` | `ca-bundle.pem` |
| Java, Electron apps | not handled | Java needs the CA imported into a trust store with `keytool`; Electron apps are not verified |

`ca-bundle.pem` is written next to the CA by `inveil browser-setup` and removed with it. It is a snapshot of the operating system's root certificates taken at that moment plus the inveil CA, so roots added or removed later are not reflected until you run `inveil browser-setup` again. Every runtime in the table that has variables also gets `HTTPS_PROXY` and `NO_PROXY` pointing at the browser proxy. A program that is not in the table gets the proxy plus the Node and Codex CA variables, as before.

## Claude Code managed settings (`--managed`)

`inveil install --managed` writes `ANTHROPIC_BASE_URL` to a drop-in file in Claude Code's machine-wide managed settings directory, which outranks user and project settings:

| OS | File |
|---|---|
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.d/50-inveil.json` |
| Linux and WSL | `/etc/claude-code/managed-settings.d/50-inveil.json` |
| Windows | `C:\Program Files\ClaudeCode\managed-settings.d\50-inveil.json` |

The directories and the `managed-settings.d/` drop-in mechanism are from <https://code.claude.com/docs/en/managed-settings>; the `env` key in any settings file is documented at <https://code.claude.com/docs/en/settings-reference#env>. The command needs write access to that directory and stops before changing anything if it does not have it; run it from an elevated shell (`sudo` or an administrator terminal). It does only that one write, from the rules already held (no network, no sign-in), and nothing in a home folder: the file is written atomically with mode 0644 into directories of mode 0755, and a symlink at the file or either directory is refused. An elevated shell cannot trust `HOME` (under `sudo` it may be the user's or root's), so it refuses the per-user install, and refuses `--managed` too unless `data_dir` is set in the system-wide configuration file, since the default data directory is under the home folder. Run the per-user part afterwards, as your own user without elevation: `inveil install`. `inveil uninstall` run elevated removes only the drop-in file; run it again as your user for the rest.

## Check it

```sh
inveil doctor          # human-readable
inveil doctor --json   # for scripts; exits 1 if any enabled tool is Not covered
```

`doctor` decides the API proxy is running only when the port answers `GET /health` with this program's version, so another program on the port, or an older inveil that was never restarted, shows as not running; the browser proxy is checked by connecting only. It also prints a warning, and marks every tool Needs setup, while `dry_run` is on (findings are logged but nothing is blocked) or the signed rules have expired. `doctor` changes nothing and prints no secrets. It does not report a heartbeat time: the client does not store one.

## Finding out what a new tool sends

```sh
inveil discover claude.ai --record
```

Developer command, off unless you pass `--record`. It runs its own recording proxy on the browser port (stop the service first), decrypts only the host you name, and passes everything through untouched. It keeps the host, method, path (identifiers collapsed to `{id}`, no query string), content type and a format guess made from the content type. It never reads request or response bodies, cookies or other headers, and prints a JSON summary when you press Ctrl-C. The host must be covered by the browser CA: add its domain to `ca_domains` in a rules file you sign, then run `inveil browser-setup`. Use the output to write a catalog entry.
