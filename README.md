# sigil

> Claude can sign, but never see.

`sigil` is a local signing daemon and Claude Code integration that lets agentic coding tools use private keys without ever putting key material in the model's context window.

**Status:** pre-alpha. Threat model is committed before the code. Do not use this with real funds yet. Build plan and current progress live in the [tracking issue](https://github.com/cdrn/sigil/issues/9).

## What it is

Three components that work together:

1. **`sigild`** — a long-running local daemon that holds unlocked keys in process memory (zeroized on shutdown; mlock against swap is planned, see [THREAT_MODEL.md](./THREAT_MODEL.md)) and exposes signing operations over a Unix socket. Keys at rest are encrypted with XChaCha20-Poly1305 and an Argon2id-derived key.
2. **`sigil-mcp`** — an MCP server that Claude (or any agentic tool) talks to. It forwards signing requests to `sigild` and returns signatures. Claude never sees key material — only opaque handles like `eth:executor`.
3. **Hooks (the wards)** — `sigil init` installs PreToolUse and PostToolUse hooks into `.claude/settings.json` that block `Read` and `Bash` from touching key paths, and redact key-shaped strings from tool output.

## What it isn't

- Not a hardware wallet replacement. If you can use a Ledger or YubiKey, do that.
- Not a custody solution. It runs on your laptop or VPS and protects you from one specific class of failure: leaking key material through an LLM agent.
- Not a substitute for policy. The library prevents *ingestion* of keys; the policy engine prevents *misuse* of signing authority. Both matter — see the threat model.

## How it will work (sketch)

```bash
# one-time setup
sigil init                          # installs hooks into ~/.claude/settings.json
sigil up                            # starts the daemon, unlocks keys via OS keychain

# register a key with policy
sigil portal add executor \
  --type eth \
  --key-file ~/keys/bot.key \
  --policy ./policies/executor.toml

# Claude now sees `eth:executor` as a portal it can sign with,
# but cannot read the key file or anything under ~/.sigil
```

A policy file looks like:

```toml
[portal.executor]
chain_ids = [1, 42161, 8453]
allow_to = ["0xRouter...", "0xExecutor..."]
max_value_wei = "100000000000000000"   # 0.1 ETH per tx
max_value_per_hour_wei = "500000000000000000"
allowed_selectors = ["0xa9059cbb", "0x095ea7b3"]   # transfer, approve
require_confirm_above_wei = "10000000000000000"    # push to phone for human ack
```

## Supply chain posture

Key-management libraries die from supply chain compromise, not from clever attacks on the code. Given the npm ecosystem in 2026 (Mini Shai-Hulud, Axios, pgserve, TanStack), `sigil` commits to:

- **Zero install scripts.** No `postinstall`, `preinstall`, `prepare`. CI-enforced.
- **Minimal dependencies.** Core sign path uses [`@noble/secp256k1`](https://github.com/paulmillr/noble-secp256k1) and `@noble/hashes` (audited, zero-dep). No viem in the core daemon.
- **No Bun.** Plain Node only. Bun is currently being weaponized by Mini Shai-Hulud as an evasion layer; we will not give that pattern any cover.
- **Provenance attestations** on every npm release via GitHub Actions trusted publishing.
- **Signed standalone binaries** from GitHub Releases for users who'd rather not touch npm.
- **Reproducible builds + SBOM** published with each release.
- **No long-lived publish tokens.** OIDC only.

## Threat model

See [THREAT_MODEL.md](./THREAT_MODEL.md). Read it before trusting this with anything.

## License

Apache License 2.0. See [LICENSE](./LICENSE).
