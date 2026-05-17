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

1. `sigil-mcp` opens a Unix socket at `~/.sigil/control.sock` (chmod 0600).
2. The user runs `sigil unlock` in a separate terminal; the CLI prompts for the passphrase, connects to the socket, and sends `{method: "unlock", passphraseB64: ...}`.
3. `sigil-mcp` decrypts every keyfile in `~/.sigil/keys/`, populates the in-memory table, zeroizes the passphrase buffer.

This shape was chosen so the agent has no path to trigger unlock — only a human at the local TTY can. `sigil lock` zeroizes the in-memory table without killing the process; subsequent signs return `DAEMON_LOCKED` again until the next `sigil unlock`.

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

Defenses (policy engine, per portal — planned, issue [#3](https://github.com/cdrn/sigil/issues/3)):
- Destination allowlists (`allow_to`)
- Per-tx and rolling-window value caps
- Allowed function selectors (only `transfer`, `approve`, etc.)
- Chain ID allowlists
- Out-of-band human confirmation above a configurable value threshold (push to ntfy / Pushover / Telegram / Apple Push), issue [#4](https://github.com/cdrn/sigil/issues/4)
- Append-only audit log with monotonic counter (already implemented)

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
- **Multi-window:** the first `sigil-mcp` to start owns `~/.sigil/control.sock`. Subsequent sessions in other Claude windows still run, but their `sigil-mcp` cannot be reached by `sigil unlock` — only the first one is addressable. Phase C of [#23](https://github.com/cdrn/sigil/issues/23) will add per-PID sockets + a flock'd audit log so multi-window sessions coexist cleanly.
- Out-of-band confirmation (planned, [#4](https://github.com/cdrn/sigil/issues/4)) depends on a working push channel. If the push provider is down, high-value signs are denied, not approved.

## Reporting issues

Security issues: open a GitHub security advisory on the repo. Please do not file public issues for vulnerabilities.
