# Security Policy

`sigil` handles private keys. Security reports are the most valuable
contribution the project can receive, and they are always welcome.

## Reporting a vulnerability

**Please report privately — do not open a public issue for a vulnerability.**

Use GitHub's private vulnerability reporting:
[**Report a vulnerability**](https://github.com/cdrn/sigil/security/advisories/new).
This opens a private advisory visible only to you and the maintainers.

If you cannot use GitHub advisories, email the maintainer listed on the
[GitHub profile](https://github.com/cdrn) with the subject line
`sigil security`.

A good report includes:

- the affected version (`npm ls sigild`) or commit,
- what the issue is and why it matters (impact),
- a minimal reproduction — **please use canary/dummy values, never real
  keys, seed phrases, or credentials**, and
- any suggested fix, if you have one.

You do not need a working exploit. A precise description of the flaw is
enough.

## What to expect

This is a small pre-alpha project maintained on a best-effort basis, so
timelines are not contractual, but the intent is:

- acknowledge your report within a few days,
- confirm or dispute it, and agree a fix and disclosure timeline with you,
- credit you in the advisory and release notes unless you ask otherwise,
- publish a GitHub Security Advisory (GHSA) and a patched release when the
  fix ships.

Coordinated disclosure is appreciated: please give a reasonable window to
ship a fix before any public write-up.

## Scope

In scope — anything that undermines sigil's core promise ("Claude can sign,
but never see") or its documented controls, for example:

- key material reaching the agent's context, transcripts, or logs,
- a signing path that bypasses the policy engine, confirm gate, or audit
  log,
- the ward hooks (path blocker / output redactor) not doing what
  [`THREAT_MODEL.md`](./THREAT_MODEL.md) says they do,
- the JSON-RPC signing proxy signing without the documented authentication
  or policy checks,
- supply-chain integrity of the published `sigild` package.

Out of scope — see the "Out of scope" and "Assumptions" sections of
[`THREAT_MODEL.md`](./THREAT_MODEL.md). In particular, an attacker who
already has local code execution or can read process memory is explicitly
outside the model.

Read [`THREAT_MODEL.md`](./THREAT_MODEL.md) before reporting — it states
what sigil does and does not defend against, which will tell you whether a
behavior is a bug or a documented limitation.

## Supported versions

Pre-alpha: only the latest published `sigild` version receives security
fixes. Pin to an exact version and read the diff before upgrading.
