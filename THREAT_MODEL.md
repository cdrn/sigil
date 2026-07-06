# Threat Model

This document describes what `sigil` defends against, what it doesn't, and the assumptions it makes. Read it before deciding whether `sigil` is appropriate for your use case.

## Actors

- **The user.** Has root on the machine. Trusted.
- **The agent (e.g. Claude).** Untrusted in the specific sense that its context window can be poisoned by adversarial inputs (prompt injection from web pages, file contents, tool output). The agent itself is not malicious, but anything it ingests can become an instruction.
- **The attacker.** May control content the agent reads (web pages, repos, API responses, transaction calldata) and may have published malicious dependencies the user installs.
- **The host OS.** Trusted. If the attacker has local code execution as your user, `sigil` does not help.

## Assets

In order of value:

1. **Private key material.** Must never leave `sigil-mcp`'s address space.
2. **Signing authority.** A signature `sigil-mcp` produces on behalf of a portal is a financial action. The set of authorized actions is bounded by per-portal policy.
3. **The audit log.** Append-only record of every sign decision. Tampering with it defeats post-incident forensics.

## Runtime model

There is exactly one long-running sigil process: `sigil-mcp`, spawned by Claude Code per session via your `mcpServers` config. It dies when Claude exits.

Keys at rest are encrypted on disk in `~/.sigil/keys/<handle>.sigil` (XChaCha20-Poly1305, Argon2id-derived key). They are **not** loaded into `sigil-mcp`'s memory at startup. `sigil-mcp` boots with an empty in-memory handle table; sign requests return `DAEMON_LOCKED` until the user explicitly pushes the passphrase in.

The unlock path:

1. `sigil-mcp` opens a Unix socket at `~/.sigil/control/<pid>.sock` (chmod 0600), one per running session.
2. The user runs `sigil unlock` in a separate terminal; the CLI prompts for the passphrase, then connects to **every** socket in `~/.sigil/control/` and sends `{method: "unlock", passphraseB64: ...}` to each.
3. Each `sigil-mcp` decrypts every keyfile in `~/.sigil/keys/`, populates its own in-memory table, and zeroizes the passphrase buffer.

This shape was chosen so the agent has no path to trigger unlock — only a human at the local TTY can. `sigil lock` zeroizes the in-memory table without killing the process; subsequent signs return `DAEMON_LOCKED` again until the next `sigil unlock`.

### The JSON-RPC signing proxy surface

With a `[rpc]` block in `~/.sigil/config.toml`, `sigil-mcp` additionally listens on `127.0.0.1:<port>` and serves `eth_accounts` / `eth_signTransaction` / `eth_sendTransaction` with the configured portal's key (proxying every other method to the configured upstream node). This is a deliberate second way to reach a key, added so Foundry/Hardhat-class tooling can sign without transaction payloads transiting the agent's context. Its containment:

- **Same pipeline, no proxy privilege.** Proxy signs are dispatched through the identical daemon path as the MCP tools — policy evaluation, the out-of-band confirm gate, and the hash-chained audit log all apply. There is no signing branch unique to the proxy.
- **Mandatory shared token.** Every request must present the config token (min 16 chars, constant-time compared) as a Bearer credential or the Basic-auth password. Without it, any local process could ask a permissive-mode portal to sign arbitrary transactions. The token lives in `~/.sigil/config.toml` (0700 home dir) — it gates *other software on the machine*, not the user's own agent: when the proxy is enabled, sigil-mcp deliberately advertises the authenticated URL in the `sigil_eth_sign_transaction` tool description so the agent can drive forge/hardhat against it (the ward hooks block it from reading the config file directly). The token therefore appears in agent context and transcripts; that is accepted — it is useless without local code execution, at which point the attacker already has the config file.
- **Loopback binding + Host allowlist.** The listener binds 127.0.0.1 only and rejects any request whose `Host` header is not a loopback name, which closes DNS-rebinding attacks from a browser tab even if the token leaks into a page-visible URL.
- **Chain binding.** The proxy fills transactions with the *upstream's* `eth_chainId`; a strict policy's `chain_ids` allowlist therefore pins the proxy to the intended network, and a client-supplied `chainId` that disagrees with the upstream is rejected outright.
- **Fail-closed inheritance.** Locked handle table, policy deny, confirm deny/timeout, missing confirm transport — each surfaces as a JSON-RPC error and no signature is produced. `eth_sign`/`personal_sign`/`eth_signTypedData*` are rejected on this surface entirely.
- **Residual risk, stated plainly:** with a **permissive** portal and the token, anything that can POST to loopback signs at will — same authority the MCP tools already grant the agent, now reachable by any tool the user (or agent) runs. Use a strict policy on any proxy-exposed portal that holds real value, and a confirm threshold for the rest. The upstream node also becomes an availability and privacy dependency: it sees every proxied call and the broadcast of every signed tx.

## In scope

### 1. Preventing key ingestion by the agent

The primary threat. Failure mode: a private key ends up in the agent's context window, then in transcripts, prompt caches, cloud logs, or attacker-controlled exfiltration paths.

Defenses:
- Keys live in `sigil-mcp`'s memory only, unlocked from encrypted at-rest storage. Plaintext is zeroized on shutdown, on `sigil lock`, and on any failed unlock. mlock against swap is planned (requires a native module distributed as bundled prebuilds, see Known limitations).
- The MCP interface exposes only opaque handles (`eth:executor`), never key bytes.
- The unlock passphrase is delivered out-of-band via the control socket, not through the agent. The agent has no exposed surface that can trigger an unlock.
- PreToolUse hooks block `Read` and `Bash` access to `~/.sigil/**`, `*.pem`, `**/.env*`, `**/keystore*`, and a configurable extra list.
- PostToolUse output filter redacts hex-encoded 32-byte blobs, PEM blocks, and bip39-shaped strings from tool output before it reaches the model.

### 2. Bounding signing authority

A defended key still loses you money if the agent can be tricked into signing the wrong payload. Prompt injection through transaction calldata, web content, or repo files can redirect signing intent.

The policy engine (per-portal `~/.sigil/policy/<handle>.toml`) is the layer that bounds this. v1 ships static checks; further work is staged in [#3](https://github.com/cdrn/sigil/issues/3) and [#4](https://github.com/cdrn/sigil/issues/4).

**Shipped (v1):**
- Two-mode policy. `permissive` mode (default for `sigil portal add`) does no checks — useful for users who only want the key-isolation guarantee. `strict` mode enforces every rule below.
- Destination allowlist (`allow_to`).
- Chain ID allowlist (`chain_ids`).
- Per-tx value cap (`max_value_wei`).
- Function selector allowlist (`allowed_selectors`) — 4-byte selector match, no calldata decoding.
- Contract creation (`to: null`) denied by default; opt in with `allow_contract_creation = true`. Initcode is arbitrary code that no allowlist can vet, so even when enabled a deploy still respects `max_value_wei` and is **always routed to the out-of-band confirm gate** — never auto-allowed. sigil-mcp refuses to start if a strict policy enables it without a confirm transport configured.
- On/off toggles for personal_sign (`allow_message_signing`) and EIP-712 typed data (`allow_typed_data`).
- Append-only hash-chained audit log records both allow AND deny decisions. Denies are the prompt-injection canary.
- Runtime fail-closed when the policy file is missing for a portal — keys can't be used without an explicit decision.
- **Solana (SVM) key reuse.** A portal's 32-byte secret doubles as an ed25519 seed, so one secret controls both an EVM (secp256k1) and a Solana (ed25519) address. This is *shared fate* by construction: compromising the secret compromises both chains. There is no known attack that combines observed ECDSA and EdDSA signatures to recover the key — both schemes are signature-secure — so reuse adds no cross-protocol weakness beyond "it is literally the same secret." SVM signing is gated by its own policy fields (`allow_svm_message_signing`, `svm_allow_to`, `svm_max_lamports`, `require_confirm_above_lamports`).
- **SVM policy is decode-limited.** Unlike EVM, Solana hides most transaction semantics behind account indices and on-chain state. sigil only decodes **native System-Program SOL transfers** offline; everything else (SPL tokens, arbitrary programs, address-lookup-table accounts) is *not* auto-allowed — it is routed to the out-of-band confirm gate (and in strict mode with no confirm transport, denied). Auto-allow is all-or-nothing: a tx signs without a human tap only if every instruction decoded and passed policy, which closes the "hide a drain behind a recognized transfer" smuggling vector. sigil signs the serialized message bytes the caller provides; it does not fetch on-chain state.

**Planned:**
- Rolling-window value caps (`max_value_per_hour_wei`, etc.) backed by a per-portal ledger with flock for multi-instance safety.
- EIP-712 domain + primary-type allowlists (today `allow_typed_data` is binary; OpenSea-style approvals deserve finer control).
- Decoded-calldata arg checks ("allow `transfer(addr, amt)` only when `amt <= 100e18` and `addr in list`"). Needs a BYO-ABI registry per portal.
- Out-of-band human confirmation above a configurable value threshold (push to ntfy / Pushover / Telegram / Apple Push), [#4](https://github.com/cdrn/sigil/issues/4).

### 3. Supply chain compromise of `sigil` itself

Given the 2026 npm threat landscape, a compromised release of `sigil` would be catastrophic. Defenses:

- Zero install scripts (`postinstall`, `preinstall`, `prepare`). CI-enforced.
- Minimal, audited dependencies (`@noble/*` family, plain Node stdlib).
- Provenance attestations via GitHub Actions trusted publishing (OIDC, no long-lived tokens) — planned for v0.1.0, not yet in place.
- Signed standalone binaries as an alternative distribution channel — planned for v0.1.0.
- Reproducible builds, published SBOM, public release checksums — planned for v0.1.0.
- No Bun in any distributed artifact.

## Out of scope

`sigil` does not defend against:

- **Local code execution as your user.** If an attacker can run code as `$USER`, they can `ptrace` `sigil-mcp`, read mlock'd memory, connect to the control socket and unlock, or simply call the MCP tools. `sigil` makes this harder (audit log will show it, policy will apply once #3 lands) but does not prevent it.
- **Root or kernel compromise.** mlock prevents swap; it does not prevent a root user from reading process memory.
- **Side channels on shared hardware.** Cache timing, Rowhammer, etc.
- **Physical access to an unlocked machine.**
- **Malicious user.** If you're trying to protect keys from yourself, you want a hardware wallet, not `sigil`.
- **Compromise of upstream cryptographic primitives.** We rely on `@noble/*` being correct. If secp256k1 is broken, everyone has bigger problems.
- **Confused-deputy at the policy boundary.** If your policy says "any tx to 0xRouter is fine" and the router happens to forward arbitrary calldata, `sigil` will sign whatever the agent asks. Policies must be written defensively.

## Assumptions

- The user installs `sigil` through a trusted channel (signed release, verified npm provenance, or built from source).
- The host OS enforces standard process isolation and respects file permissions on `~/.sigil/` (the directory is 0700; keyfiles and the control socket are 0600).
- The user's OS keychain (or chosen unlock mechanism) is not compromised.
- Clock skew on the host is bounded (matters for rolling-window policy and audit timestamps).

## Known limitations

- The hook-based path blocker is best-effort: it covers `Read` and `Bash`, but a sufficiently creative agent could still ask another tool to do the read. The defense in depth is that even if a key file is read, its contents are redacted by the output filter before reaching the model. And, given the unlock model, reading the encrypted keyfile alone yields nothing — the agent would also need the passphrase, which is never in its context.
- The output redaction filter has false negatives (keys with non-standard encoding) and false positives (legitimate hex blobs). It is not a replacement for the path blocker; it's a second line.
- The MCP stdio is the agent's exposed surface; the control socket is the user's exposed surface. Both are unauthenticated within the user's session — any process running as `$USER` can talk to either. This is consistent with the threat model (we don't defend against local user compromise) but worth stating explicitly.
- **mlock is not yet implemented.** Plaintext key material lives in a regular `Buffer` that is zeroized on `sigil-mcp` shutdown, on `sigil lock`, or on a failed unlock. This means keys are vulnerable to being paged to swap on a memory-pressured system. mlock requires a native module, which we will ship as bundled prebuilds (no install scripts) rather than via a compile-on-install dependency. Tracked as a planned layer.
- **Passphrase in transit through V8 strings.** The control socket carries the passphrase base64-encoded inside a JSON message. The CLI's `Buffer` and the server's decoded `Buffer` are zeroized after use, but the intermediate JSON string sits in V8's string heap and cannot be reliably wiped. This is the same trade-off as `readPassphrase`'s internal accumulator and is considered acceptable for v0.x; mitigations would require either a custom binary framing or a fully native crypto path.
- **Multi-window:** each `sigil-mcp` binds its own `~/.sigil/control/<pid>.sock`, and `sigil unlock`/`lock`/`status` fan out across all of them, so every open Claude window is reachable from one CLI call. Each session keeps a separate in-memory handle table and unlocks independently; the passphrase is sent (base64 in JSON, same transit caveat as above) to each live session. A window opened after an unlock starts locked until the next `sigil unlock`. Sockets orphaned by hard-killed sessions are unlinked on the next CLI call. Keys still never outlive the sessions that hold them — see [#23](https://github.com/cdrn/sigil/issues/23). The fan-out widens the control surface from one well-known socket to "every `<pid>.sock` in the directory": a hostile process running as `$USER` could plant its own listener in `~/.sigil/control/` and harvest the passphrase on the next `sigil unlock`. The `~/.sigil/` tree is 0700 so this requires same-user code execution, which is already out of scope (above); it is not a new trust boundary, only a larger surface within the existing one.
- Out-of-band confirmation (planned, [#4](https://github.com/cdrn/sigil/issues/4)) depends on a working push channel. If the push provider is down, high-value signs are denied, not approved.

## Reporting issues

Security issues: open a GitHub security advisory on the repo. Please do not file public issues for vulnerabilities.
