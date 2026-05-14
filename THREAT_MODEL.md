# Threat Model

This document describes what `sigil` defends against, what it doesn't, and the assumptions it makes. Read it before deciding whether `sigil` is appropriate for your use case.

## Actors

- **The user.** Has root on the machine. Trusted.
- **The agent (e.g. Claude).** Untrusted in the specific sense that its context window can be poisoned by adversarial inputs (prompt injection from web pages, file contents, tool output). The agent itself is not malicious, but anything it ingests can become an instruction.
- **The attacker.** May control content the agent reads (web pages, repos, API responses, transaction calldata) and may have published malicious dependencies the user installs.
- **The host OS.** Trusted. If the attacker has local code execution as your user, `sigil` does not help.

## Assets

In order of value:

1. **Private key material.** Must never leave `sigild`'s address space.
2. **Signing authority.** A signature `sigild` produces on behalf of a portal is a financial action. The set of authorized actions is bounded by per-portal policy.
3. **The audit log.** Append-only record of every sign decision. Tampering with it defeats post-incident forensics.

## In scope

### 1. Preventing key ingestion by the agent

The primary threat. Failure mode: a private key ends up in the agent's context window, then in transcripts, prompt caches, cloud logs, or attacker-controlled exfiltration paths.

Defenses:
- Keys live in `sigild`'s memory only, unlocked from encrypted at-rest storage.
- The MCP interface exposes only opaque handles (`eth:executor`), never key bytes.
- PreToolUse hooks block `Read` and `Bash` access to `~/.sigil/**`, `*.pem`, `**/.env*`, `**/keystore*`, and a configurable extra list.
- PostToolUse output filter redacts hex-encoded 32-byte blobs, PEM blocks, and bip39-shaped strings from tool output before it reaches the model.

### 2. Bounding signing authority

A defended key still loses you money if the agent can be tricked into signing the wrong payload. Prompt injection through transaction calldata, web content, or repo files can redirect signing intent.

Defenses (policy engine, per portal):
- Destination allowlists (`allow_to`)
- Per-tx and rolling-window value caps
- Allowed function selectors (only `transfer`, `approve`, etc.)
- Chain ID allowlists
- Out-of-band human confirmation above a configurable value threshold (push to Pushover / Telegram / Apple Push)
- Append-only audit log with monotonic counter

### 3. Supply chain compromise of `sigil` itself

Given the 2026 npm threat landscape, a compromised release of `sigil` would be catastrophic. Defenses:

- Zero install scripts (`postinstall`, `preinstall`, `prepare`). CI-enforced.
- Minimal, audited dependencies (`@noble/*` family, plain Node stdlib).
- Provenance attestations via GitHub Actions trusted publishing (OIDC, no long-lived tokens).
- Signed standalone binaries as an alternative distribution channel.
- Reproducible builds, published SBOM, public release checksums.
- No Bun in any distributed artifact.

## Out of scope

`sigil` does not defend against:

- **Local code execution as your user.** If an attacker can run code as `$USER`, they can `ptrace` the daemon, read mlock'd memory, or simply ask `sigild` to sign things over the socket. `sigil` makes this harder (audit log will show it, policy still applies) but does not prevent it.
- **Root or kernel compromise.** mlock prevents swap; it does not prevent a root user from reading process memory.
- **Side channels on shared hardware.** Cache timing, Rowhammer, etc.
- **Physical access to an unlocked machine.**
- **Malicious user.** If you're trying to protect keys from yourself, you want a hardware wallet, not `sigil`.
- **Compromise of upstream cryptographic primitives.** We rely on `@noble/*` being correct. If secp256k1 is broken, everyone has bigger problems.
- **Confused-deputy at the policy boundary.** If your policy says "any tx to 0xRouter is fine" and the router happens to forward arbitrary calldata, `sigil` will sign whatever the agent asks. Policies must be written defensively.

## Assumptions

- The user installs `sigil` through a trusted channel (signed release, verified npm provenance, or built from source).
- The host OS enforces standard process isolation.
- The user's OS keychain (or chosen unlock mechanism) is not compromised.
- Clock skew on the host is bounded (matters for rolling-window policy and audit timestamps).

## Known limitations

- The hook-based path blocker is best-effort: it covers `Read` and `Bash`, but a sufficiently creative agent could still ask another tool to do the read. The defense in depth is that even if a key file is read, its contents are redacted by the output filter before reaching the model.
- The output redaction filter has false negatives (keys with non-standard encoding) and false positives (legitimate hex blobs). It is not a replacement for the path blocker; it's a second line.
- The MCP socket is currently unauthenticated within the user's session. Any process running as `$USER` can connect to it. This is consistent with the threat model (we don't defend against local user compromise) but worth stating explicitly.
- Out-of-band confirmation depends on a working push channel. If the push provider is down, high-value signs are denied, not approved.

## Reporting issues

Security issues: open a GitHub security advisory on the repo. Please do not file public issues for vulnerabilities.
