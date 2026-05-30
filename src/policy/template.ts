/**
 * TOML template strings written by `sigil portal add`. Hand-written rather
 * than serialized so we can include explanatory comments — TOML serializers
 * generally strip those.
 */

export const PERMISSIVE_TEMPLATE = `# sigil policy file — permissive mode (default)
#
# This portal will sign anything the agent asks for. Your private key is
# still encrypted at rest and never enters Claude's context, but signing
# authority is unbounded.
#
# To restrict what this portal can sign, run:
#
#   sigil portal remove <handle>
#   sigil portal add <handle> --key-file <path> --strict
#
# ...and edit the resulting policy file. Or just change "permissive" below
# to "strict" and add the rules in the commented template at:
# https://github.com/cdrn/sigil#policy-engine

mode = "permissive"
`;

export const STRICT_TEMPLATE = `# sigil policy file — strict mode
#
# Every sign request is checked against the rules below before the key is
# used. Edit the values to fit your portal. Anything you leave at the
# default-zero/empty state will deny.

mode = "strict"

# Allowed chain IDs (decimal). At least one is required.
#   1 = ethereum mainnet
#   8453 = base
#   42161 = arbitrum one
#   10 = optimism
#   11155111 = sepolia testnet
chain_ids = [1]

# Allowed destination addresses (lowercase 0x-prefixed). Empty = no tx allowed.
# Example:
#   allow_to = ["0x000000000000000000000000000000000000dead"]
allow_to = []

# Per-tx value cap in wei. Default 0 = no ETH sends allowed at all.
# 0.1 ether = "100000000000000000"
# 1 ether   = "1000000000000000000"
# Quoted because uint256 doesn't fit in a TOML integer.
max_value_wei = "0"

# 4-byte function selectors that are callable. Empty = pure ETH sends only.
# Common selectors:
#   "0xa9059cbb"  ERC-20 transfer(address,uint256)
#   "0x095ea7b3"  ERC-20 approve(address,uint256)
#   "0x23b872dd"  ERC-20 transferFrom(address,address,uint256)
allowed_selectors = []

# EIP-191 personal_sign — typically safe (used by Sign-In With Ethereum and
# similar login flows). Set true to permit.
allow_message_signing = false

# EIP-712 typed data — CAN authorize off-chain financial actions (Permit,
# OpenSea orders, gasless approvals). Treat with the same care as signing
# transactions. Set true to permit.
allow_typed_data = false

# Optional: above this wei amount, sigil pushes a notification to your
# phone and waits for an explicit approve/deny tap before signing. Must be
# strictly less than max_value_wei. Requires a [confirm.ntfy] block in
# ~/.sigil/config.toml; without one, sigil-mcp refuses to start.
# Example: confirm anything above 0.01 ETH.
# require_confirm_above_wei = "10000000000000000"
`;

export type PolicyMode = 'permissive' | 'strict';

export function policyTemplate(mode: PolicyMode): string {
  return mode === 'permissive' ? PERMISSIVE_TEMPLATE : STRICT_TEMPLATE;
}
