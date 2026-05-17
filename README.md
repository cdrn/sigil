# sigil

> Claude can sign, but never see.

`sigil` is a local signing tool and Claude Code integration that lets agentic coding tools use private keys without ever putting key material in the model's context window.

**Status:** pre-alpha. The MCP server, CLI, unlock flow, ward hooks, and policy engine (static checks) all work end-to-end. Out-of-band confirmation, rolling-window value caps, and EIP-712 domain allowlists are not yet implemented. Until they land — and until the supply-chain attestations promised for v0.1.0 ship — **do not use this with real funds yet.** Build plan lives in the [tracking issue](https://github.com/cdrn/sigil/issues/9).

## What it is

One MCP server process, four bins, three runtime deps:

1. **`sigil-mcp`** — the only thing that runs. Claude Code spawns it per session via your `mcpServers` config; it dies when Claude exits. Holds unlocked keys in process memory (zeroized on shutdown, `sigil lock`, or unlock-failure; mlock against swap is planned). Keys at rest are encrypted with XChaCha20-Poly1305 and an Argon2id-derived key. Signs over stdio using a DIY MCP wire protocol (~200 lines, no SDK dep). Claude never sees key material — only opaque handles like `eth:executor`.
2. **`sigil`** — control CLI. `init`, `status`, `portal add`/`list`/`remove`, `unlock`, `lock`.
3. **`sigil-hook-pre` / `sigil-hook-post`** — Claude Code hook binaries that block reads of common key paths and redact key-shaped strings from tool output.

`sigil-mcp` boots **locked**: empty in-memory handle table, no keys loaded. Sign methods return `DAEMON_LOCKED` (-32003) with a "run sigil unlock" message until you push the passphrase in from a separate terminal via `sigil unlock`. That CLI connects to a Unix socket at `~/.sigil/control.sock` (0600) that `sigil-mcp` opens at startup. After unlock, signs work for the rest of the session; `sigil lock` zeroizes the table without killing the process.

Sign methods exposed today: EIP-191 personal_sign, EIP-1559 + legacy transactions, EIP-712 typed data.

## What it isn't

- Not a hardware wallet replacement. If you can use a Ledger or YubiKey, do that.
- Not a custody solution. It runs on your laptop or VPS and protects you from one specific class of failure: leaking key material through an LLM agent.
- A first cut of *bounding signing authority* via the policy engine — but not the full thing. v1 covers static checks (chain ID, destination allowlist, per-tx value cap, function-selector allowlist, on/off toggles for personal_sign and EIP-712). Rolling-window caps, EIP-712 domain allowlists, and out-of-band human confirmation are tracked in [#3](https://github.com/cdrn/sigil/issues/3) + [#4](https://github.com/cdrn/sigil/issues/4) and will land incrementally.

## Install

```sh
npm install -g sigild
```

This drops four binaries on your `$PATH`: `sigil`, `sigil-mcp`, `sigil-hook-pre`, `sigil-hook-post`. (The package name on npm is `sigild` for legacy reasons; the bins do not include a daemon any more.)

Requires Node 22+.

## Quick start

```sh
# 1. Wire sigil into Claude Code (project-scoped). Pass --user to do it globally.
sigil init

# 2. Encrypt a private key into sigil's keystore. Source key is deleted by default.
#    Accepts either 32 raw bytes or 64 hex chars (with optional 0x prefix).
sigil portal add eth:bot --key-file ./bot.key
# → prompts for a passphrase, derives the address, writes
#   ~/.sigil/keys/eth:bot.sigil  AND  ~/.sigil/policy/eth:bot.toml (permissive)
#
# Pass --strict to start with a locked-down policy template you fill in
# before any sign succeeds:
#   sigil portal add eth:bot --key-file ./bot.key --strict

# 3. Open Claude Code. It spawns sigil-mcp automatically via your MCP config.
#    sigil-mcp boots locked — the first sign attempt will return DAEMON_LOCKED.

# 4. In a separate terminal, push the passphrase to the running sigil-mcp.
sigil unlock
# → prompts for the passphrase, decrypts every keyfile in ~/.sigil/keys/

# 5. Use Claude Code. The four sigil_* tools will work for the rest of the session.

# Optional: re-lock without restarting Claude.
sigil lock
```

If you close Claude Code, `sigil-mcp` exits and its memory is wiped. Open a new session and `sigil unlock` again — the encrypted keyfiles on disk persist.

## CLI reference

```text
sigil init [--user]
  Write the MCP server registration and the ward hooks into
  .claude/settings.json. With --user, writes ~/.claude/settings.json
  instead. Idempotent — preserves your unrelated settings.

sigil portal add <handle> --key-file <path> [--no-remove-source] [--strict]
  Encrypt the key with your passphrase and store it at
  ~/.sigil/keys/<handle>.sigil (mode 0600). Handle format is
  <kind>:<name> where kind is "eth". The source key file is deleted
  by default — pass --no-remove-source to keep it.
  Also writes ~/.sigil/policy/<handle>.toml — permissive by default
  (signs anything), or use --strict for a locked-down template you
  fill in before signs succeed.

sigil policy show <handle>
  Print the current policy file for a portal. Validates schema; exits
  1 if the file is missing or malformed.

sigil portal list
  List the encrypted keyfiles on disk with their derived addresses.
  Requires the passphrase.

sigil portal remove <handle>
  Delete a keyfile from disk.

sigil unlock
  Prompt for the passphrase and push it to the running sigil-mcp over
  the control socket. After unlock, sign calls succeed for the rest
  of the Claude session. Fails if sigil-mcp is not running (start a
  Claude Code session first) or if already unlocked.

sigil lock
  Tell sigil-mcp to zeroize and clear its in-memory keys. Re-unlock
  with sigil unlock — sigil-mcp keeps running.

sigil status
  Report whether sigil-mcp is running (probes ~/.sigil/control.sock),
  its PID, whether it's unlocked, what portals it has loaded, and
  how many keyfiles exist on disk. Does not require the passphrase.
```

Set `SIGIL_HOME` to override `~/.sigil`. Set `SIGIL_CONTROL_SOCK` to override the control socket path.

## Multi-window behaviour

Each Claude Code window spawns its own `sigil-mcp`. They share the on-disk keyfiles + audit log but have separate in-memory handle tables — you `sigil unlock` once per window. (The first MCP to start owns `control.sock`; further sessions will get their own socket once flock-based per-instance sockets land in Phase C of [#23](https://github.com/cdrn/sigil/issues/23). Until then, only the first window's `sigil-mcp` is reachable from the CLI.)

OS-keychain integration (planned, v0.3) will make unlock zero-touch for users who set it up.

## Policy engine

Once a portal is unlocked, signing authority over its key is real. To bound the blast radius of a successful prompt injection, every portal has a policy file at `~/.sigil/policy/<handle>.toml`. Two modes:

**Permissive** (default for `sigil portal add`): no rules. Sign anything the agent asks. The key isolation guarantees still hold — your key never enters the agent's context — but the unlocked portal can be made to sign whatever an attacker can get the agent to ask for. Useful for: testnet bots, demo flows, anyone who only cares about the context-window protection.

**Strict** (opt in with `--strict`): every sign request is checked. Generated template:

```toml
mode = "strict"

chain_ids = [1]                           # allowed chain IDs
allow_to = []                             # allowed destination addresses (lowercase 0x)
max_value_wei = "0"                       # per-tx cap, in wei, as decimal string
allowed_selectors = []                    # 4-byte function selectors, e.g. "0xa9059cbb"

allow_message_signing = false             # EIP-191 personal_sign (e.g. SIWE)
allow_typed_data = false                  # EIP-712 (Permit, OpenSea — can be financial)
```

A failed rule throws `POLICY_DENIED` (-32001) back to the agent with the human-readable reason ("tx denied — value X exceeds max_value_wei Y"), and the deny is appended to the hash-chained audit log alongside allows. Denies are forensically the more interesting half — they're the prompt-injection canary.

What's deferred to follow-up PRs (still in [#3](https://github.com/cdrn/sigil/issues/3)): rolling-window value caps (e.g. 1 ETH/day per portal), EIP-712 domain + primary-type allowlists, decoded-calldata arg checks, and the `require_confirm_above_wei` outcome that hooks into the OOB push gate ([#4](https://github.com/cdrn/sigil/issues/4)).

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
npm test         # builds + runs ~330 tests; should finish in under 10s
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the PR-per-layer workflow.

## License

Apache License 2.0. See [LICENSE](./LICENSE).
