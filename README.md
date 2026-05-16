# sigil

> Claude can sign, but never see.

`sigil` is a local signing daemon and Claude Code integration that lets agentic coding tools use private keys without ever putting key material in the model's context window.

**Status:** pre-alpha (v0.0.1 published as a name-stake placeholder). The core pieces — daemon, MCP server, CLI, and ward hooks — all work end-to-end. The policy engine and out-of-band confirmation gate are not yet implemented; until they land, sigil signs anything an authenticated socket caller asks. **Do not use this with real funds yet.** Build plan lives in the [tracking issue](https://github.com/cdrn/sigil/issues/9).

## What it is

Four bins, one package, three runtime deps:

1. **`sigild`** — long-running local daemon. Holds unlocked keys in process memory (zeroized on shutdown; mlock against swap is planned, see [THREAT_MODEL.md](./THREAT_MODEL.md)) and exposes signing operations over a Unix socket. Keys at rest are encrypted with XChaCha20-Poly1305 and an Argon2id-derived key.
2. **`sigil-mcp`** — an MCP server (DIY wire protocol; no SDK dep) that Claude talks to over stdio. It forwards signing requests to `sigild`. Claude never sees key material — only opaque handles like `eth:executor`.
3. **`sigil`** — control CLI. `init`, `status`, `portal add`/`list`/`remove`.
4. **`sigil-hook-pre` / `sigil-hook-post`** — Claude Code hook binaries that block reads of common key paths and redact key-shaped strings from tool output.

Sign methods exposed today: EIP-191 personal_sign, EIP-1559 + legacy transactions, EIP-712 typed data.

## What it isn't

- Not a hardware wallet replacement. If you can use a Ledger or YubiKey, do that.
- Not a custody solution. It runs on your laptop or VPS and protects you from one specific class of failure: leaking key material through an LLM agent.
- Not yet a substitute for policy. The library prevents *ingestion* of keys; the policy engine (issue [#3](https://github.com/cdrn/sigil/issues/3)) will prevent *misuse* of signing authority. Both matter — see the threat model.

## Install

```sh
npm install -g sigild
```

This drops five binaries on your `$PATH`: `sigild`, `sigil`, `sigil-mcp`, `sigil-hook-pre`, `sigil-hook-post`.

Requires Node 22+.

## Quick start

```sh
# 1. Wire sigil into Claude Code (project-scoped). Pass --user to do it globally.
sigil init

# 2. Encrypt a private key into sigil's keystore. Source key is deleted by default.
#    Accepts either 32 raw bytes or 64 hex chars (with optional 0x prefix).
sigil portal add eth:bot --key-file ./bot.key
# → prompts for a passphrase, derives address, writes ~/.sigil/keys/eth:bot.sigil

# 3. Start the daemon in a separate terminal (or tmux pane).
sigild
# → prompts for the same passphrase, loads every keyfile in ~/.sigil/keys/

# 4. Verify everything's up.
sigil status

# 5. Use Claude Code. It will discover the four sigil_* tools via MCP and call them.
```

Today `sigild` runs in the foreground. A `sigil up` backgrounding command is planned for v0.2; for now run it in a tmux/screen pane or pipe through `nohup`.

## CLI reference

```text
sigil init [--user]
  Write the MCP server registration and the ward hooks into
  .claude/settings.json. With --user, writes ~/.claude/settings.json
  instead. Idempotent — preserves your unrelated settings.

sigil portal add <handle> --key-file <path> [--no-remove-source]
  Encrypt the key with your passphrase and store it at
  ~/.sigil/keys/<handle>.sigil (mode 0600). Handle format is
  <kind>:<name> where kind is "eth". The source key file is deleted
  by default — pass --no-remove-source to keep it.

sigil portal list
  List the encrypted keyfiles on disk with their derived addresses.
  Requires the passphrase.

sigil portal remove <handle>
  Delete a keyfile from disk.

sigil status
  Report whether sigild is running, what portals it has loaded,
  and how many keyfiles exist on disk. Does not require the passphrase.
```

Set `SIGIL_HOME` to override `~/.sigil`. Set `SIGIL_SOCK` to override the socket path.

## Supply chain posture

Key-management libraries die from supply chain compromise, not from clever attacks on the code. Given the npm ecosystem in 2026 (Mini Shai-Hulud, Axios, pgserve, TanStack), `sigil` commits to:

- **Zero install scripts.** No `postinstall`, `preinstall`, `prepare`. CI-enforced (planned: a CI guard that fails if any dep adds one).
- **Three runtime deps, all version-pinned** (no caret ranges):
  - [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers) for XChaCha20-Poly1305
  - [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) for Argon2id, keccak256, sha2, HMAC
  - [`@noble/secp256k1`](https://github.com/paulmillr/noble-secp256k1) for ECDSA
  All by paulmillr, audited, zero transitive deps.
- **No MCP SDK.** The official `@modelcontextprotocol/sdk` pulls 92 transitive deps (ajv, hono, cors, cross-spawn, etc) — unacceptable surface. We implement the MCP wire protocol directly in ~200 lines.
- **No Bun.** Plain Node only. Bun is currently being weaponized by Mini Shai-Hulud as an evasion layer; we will not give that pattern any cover.
- **Planned for v0.1.0** (the real release, not this 0.0.1 placeholder):
  - Provenance attestations on every npm publish via GitHub Actions trusted publishing (OIDC, no long-lived tokens)
  - SBOM (CycloneDX) attached to every release
  - Signed standalone binaries from GitHub Releases for users who'd rather not touch npm
  - Action SHA pinning rotation via Dependabot

## Threat model

See [THREAT_MODEL.md](./THREAT_MODEL.md). Read it before trusting this with anything.

## Development

```sh
git clone https://github.com/cdrn/sigil
cd sigil
npm install      # respects .npmrc ignore-scripts=true
npm test         # builds + runs ~340 tests; should finish in under 10s
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the PR-per-layer workflow.

## License

Apache License 2.0. See [LICENSE](./LICENSE).
