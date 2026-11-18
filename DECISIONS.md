# Decisions

A running log of features and the reasoning behind them: what was built, why
it was built that way, its status, and what has not been verified. Newest
first.

---

## 2026-11-17 — Transaction preview: security-review fixes

**What.** Seven findings from the review of `feat/tx-preview`, one commit
each, each with a regression test:

1. The simulation now carries the exact signed parameters — nonce, gas,
   access list and the fee fields (`maxFeePerGas`/`maxPriorityFeePerGas`
   or `gasPrice`) — in `eth_simulateV1` and the `eth_call`/
   `eth_estimateGas` fallback. A `gasLimit` below 21000 (incl. 0, which
   let the node pick its own gas) is `unavailable`, so
   `require_simulation` denies it.
2. The `eth_call` fallback only succeeds on whole-byte hex return data;
   a revert from `eth_estimateGas` is a revert.
3. Headline lists debits (outflows, NFTs out, approvals granted) before
   credits and never truncates them; symbols that collide or impersonate
   USDC/USDT/DAI/WETH/WBTC/ETH off their canonical address render as
   `"USDC"? (0x…)` with a warning; friendly verbs (wrap/unwrap/transfer/
   swap) need matching simulated behaviour; a debit with inflows from
   unverified tokens warns.
4. Every node quantity is ≤ uint256 (64 hex digits) or rejected; tx
   fields > uint256 are INVALID_PARAMS; number formatting is linear.
5. A known revert can't be downgraded to `unavailable` by malformed logs.
6. ABI names must be identifiers; control characters are stripped at the
   render boundary.
7. Array suffixes count toward the ABI type nesting limit; type strings
   are capped at 4096 chars.

**Why — choices worth recording.**

- **Fee fields vs unfunded senders.** Checked live with `validation:false`
  from the unfunded `0x2278…931c`: Sepolia reth (publicnode) accepts nonce
  and fee fields; anvil accepts any nonce but refuses fee fields when the
  sender can't pay gas × price (-32003). On exactly that error sigil
  retries once without the fee fields and records which were dropped in
  the simulation notes ("the contract saw tx.gasprice = 0"); if the retry
  is refused too, the error stands.
- **Behaviour checks only contradict, never vouch.** With no simulation
  logs (skipped, unavailable, eth_call fallback) the friendly verb stays —
  there is no evidence against it — and the debit-first headline is the
  backstop.
- **Canonical-token table is tiny on purpose.** Every one of its 23
  entries was checked on 2026-11-17 by reading `symbol()` at that address
  on its chain through publicnode RPCs (all match; Arbitrum's USDT
  reports "USD₮0", which is the USDT0 contract at the published address).
  A name with no entry on a chain (and any unknown chain) is treated as
  unverifiable, so it is quoted.

**Status.** Built on `feat/tx-preview`; all tests green.

**Unverified.** The headline can exceed 220 chars when the debits alone
are longer — by design.

---

## 2026-11-16 — Transaction preview: decode + simulate in the sign path

**What.** Every EVM transaction sigil signs (MCP tool or JSON-RPC proxy) is
decoded to English and, when a node is configured for its chain, dry-run.
The result is (a) appended to the out-of-band confirm push as a one-line
headline plus up to three warnings, (b) returned to the agent as `preview`
next to `signed`, (c) written into the audit entry (new optional,
hash-covered `preview` field, on allows and denies), and (d) fed to two new
mode-independent policy gates: `require_simulation` and `sign_on_revert`.
New pieces:

- `src/eth/abi.ts` — a hand-rolled, strict ABI decoder (no encoder) on the
  existing keccak. Bounds-checked offsets/lengths, canonical-padding checks
  on static types, and an output budget against aliased offsets. Always
  `AbiDecodeError`, never a raw `RangeError`.
- `src/preview/` — built-in descriptions (`known.ts`), user ABIs from
  `~/.sigil/abi/*.json` (`abi-dir.ts`), calldata decoding (`decode.ts`),
  simulation (`simulate.ts`), per-chain node resolution (`simulators.ts`),
  and deterministic rendering (`format.ts`).
- `[simulate]` in `config.toml` (`timeout_ms`, `[simulate.rpc]` chain id →
  URL).
- `sigil_eth_preview_transaction` MCP tool: same input as sign, no policy,
  no audit, nothing signed.
- `HandleTable.info()` so the sign path gets the portal address without
  touching or re-deriving from the key.

**Why — the main choices.**

- **`eth_simulateV1` is the primary primitive.** One RPC call returns
  status, gas, revert data and every log; with `traceTransfers` it also
  reports native ETH movements as synthetic ERC-20-style `Transfer` logs. It
  is served by geth, reth, anvil and the large hosted providers, so it is
  portable without a provider-specific trace API (`debug_traceCall`,
  Tenderly, Alchemy's simulateAssetChanges). Nodes without it get an
  `eth_call` + `eth_estimateGas` fallback: status and gas only, balance
  changes explicitly "unknown". The fallback triggers only on -32601 or a
  message saying the method is unsupported / does not exist — not on any
  node error — so a node-state error ("header not found") is reported as
  unavailable instead of silently degrading.
- **Native-ETH sentinel: both `0xEeee…EEeE` and `0x0`.** geth (and anvil,
  verified live) emit traced transfers from ERC-7528's `0xEeee…` address;
  the brief named the zero address. Both are accepted; neither can host a
  real token. The top-level `tx.value` is traced too (verified on anvil), so
  it is only added to the delta when the node did not trace the portal's
  outflow — no double counting.
- **Preview never blocks a sign when unconfigured.** With no `[simulate]`
  block, no `[rpc]` block and default policy fields, the only behaviour
  changes for existing users are richer confirm text, an extra `preview`
  field in the sign result, and a `preview` field in audit entries. Calldata
  is still decoded (offline); simulation reports `skipped`.
- **Presentation fails open-but-loud; policy fails closed.** Decoding
  mismatches, node outages, timeouts, malformed responses and even bugs in
  the preview code become warnings and an `unavailable` status — never a
  thrown error that blocks a sign. The two policy gates are the only things
  that turn the preview into a deny, and `require_simulation` treats
  "skipped", "unavailable" and a preview failure all as deny.
- **Order: static policy → preview → preview gates → confirm.** A tx the
  static policy denies never reaches the simulation node (no calldata leak
  for something we'd refuse anyway), and a human is never asked to approve
  something the simulation gate would deny.
- **The preview tool is unaudited.** It signs nothing and runs no policy,
  so there is no decision to record; auditing it would also let an agent
  flood the log with no-op entries. It still requires an unlocked portal,
  because the simulation runs *as* the portal's address.
- **Simulation sends calldata to the user's configured node only** — the
  same node class the tx would be broadcast through. The `[rpc]` proxy's
  upstream is reused for the one chain it reports (lazy `eth_chainId`,
  60 s cool-down after a failure), never for other chains.
- **Gas is excluded from balance deltas.** It depends on inclusion-time
  fees, not on what the call does; showing it would make every delta wrong
  by a varying amount.
- **Contract-chosen strings are sanitized.** Token symbols are restricted
  to a short printable set (else the address is shown); revert strings are
  JSON-quoted and clipped. Both land on the user's phone and in the agent's
  context, so they must not be able to fake sigil's own lines.
- **Determinism.** `buildTxPreview` is pure given the decode inputs and the
  node's answers, so tests pin exact text and the audit log records exactly
  what was shown.
- **User ABIs:** loaded once at boot (cheap; restart to pick up new files),
  first definition of a selector wins in sorted filename order, built-in
  descriptions keep the sentence but take the user's argument names. Bad
  files are skipped and named in every preview's footer (the preview is
  pure, so "once" means once per preview rather than once per process).
- **Small extensions beyond the brief:** `DecodedCall` carries an optional
  `short` (headline form) and `tokens` (addresses whose metadata sharpens
  the rendering, e.g. the Permit2 token); `simulatorFor` may return a
  promise (needed for the lazy `[rpc]` chain lookup); the 7-field
  SwapRouter02 `exactInputSingle` is included alongside the 8-field one;
  swap descriptions warn on a non-portal recipient and a zero minimum
  output; a deploy that `eth_simulateV1` can't build (anvil returns -32602,
  missing `to`) falls back to `eth_call`.

**Status.** Built on `feat/tx-preview`. 926 tests green (829 before) (decoder, built-ins,
user ABIs, simulator incl. fallback/timeout/revert/metadata cases, preview
rendering pinned, sign-path wiring, proxy inheritance, audit round-trip).
Verified end-to-end against a local anvil node: real `eth_simulateV1`
response shape, traced native transfer, a freshly deployed ERC-20's
`symbol()`/`decimals()`, an unlimited approve preview, a transfer signed
with its preview audited, and an overdraw denied with
`Error("TOK: balance")`. Then against a hosted Sepolia node
(publicnode, reth v2.11): USDC approve, USDC transfer and a plain ETH send
from the unfunded smoke portal. Two divergences found and fixed: reth
reports traced native transfers from `0xffff…fffe` (now a native
sentinel, so the ETH was no longer double-counted as a fake token), and a
bare revert that burned ≥95% of the gas limit is now reported as "likely
out of gas (used X of the Y gas limit)" — a USDC approve on Sepolia costs
~140k gas and had shown as a plain "execution reverted" at gas 100000.
After the fix: approve says out of gas, transfer says
`Error("ERC20: transfer amount exceeds balance")`, the ETH send shows
`-0.001 ETH` once.

**Unverified.**

- No test against mainnet nodes or the paid providers (Alchemy, Infura,
  QuickNode); their `eth_simulateV1` support and error codes are assumed to
  match geth's/reth's. A provider that rejects `validation: false` or
  `traceTransfers` would surface as `unavailable`.
- geth itself was not run; anvil and a hosted reth were.
- The out-of-gas heuristic (≥95% of the limit, no revert data) can
  misread a contract that reverts late with no reason; the message says
  "likely" for that reason.
- The real ntfy rendering of the multi-line confirm body (headline + `⚠`
  lines) was not looked at on a phone.
- Built-in descriptions for Universal Router `execute` name only the
  command count; its commands are not decoded.
- An `insufficient funds` answer from the node is reported as `unavailable`
  rather than as a revert, so `sign_on_revert = false` does not deny it
  (`require_simulation = true` does).
- Each tx is simulated alone against `latest`: a second tx that depends on
  an unbroadcast first one (approve, then swap) simulates as a revert and is
  denied under the default `sign_on_revert = false`. Documented; agents need
  to broadcast between dependent signs.
- Existing `[rpc]` proxy users get simulation on the proxy's chain without
  opting in, so a tx that simulates to a revert is now denied there by
  default. forge already simulates before broadcasting and the proxy's fill
  step already calls `eth_estimateGas`, so this should rarely bite, but it
  is a behaviour change.
- Mixed-version daemons: an older `sigil-mcp` sharing `~/.sigil/audit.log`
  does not know the `preview` field, fails the entry's hash check and
  quarantines the log. The README already requires restarting every
  `sigil-mcp` after an upgrade; this feature makes that requirement bite.
  Accepted as a known limitation after the 2026-11-17 security review, not
  fixed: the mitigation is the README rule "After upgrading sigil, restart
  every Claude window's `sigil-mcp`", and the moved-aside log is renamed,
  never deleted.
