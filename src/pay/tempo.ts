import { randomBytes } from 'node:crypto';

import { keccak256 } from '../eth/keccak.js';
import { encodeInt, rlpEncode, type RlpInput } from '../eth/rlp.js';
import { signDigest } from '../eth/secp.js';
import type { Hex } from '../eth/sign-tx.js';

/**
 * Tempo Transaction (EIP-2718 type 0x76) signing, scoped to what an MPP
 * "tempo" charge credential needs: a single-sender, fee-sponsored batch of
 * TIP-20 transfer calls, serialized in the fee-payer handoff format (magic
 * 0x78) for the server to countersign and broadcast.
 *
 * Wire layout (RLP list behind the type/magic byte):
 *   [0]  chain_id
 *   [1]  max_priority_fee_per_gas
 *   [2]  max_fee_per_gas
 *   [3]  gas_limit
 *   [4]  calls                    — list of [to, value, data]
 *   [5]  access_list
 *   [6]  nonce_key
 *   [7]  nonce
 *   [8]  valid_before             — empty when unset
 *   [9]  valid_after              — empty when unset
 *   [10] fee_token                — empty in the sender preimage under
 *                                   sponsorship (sender does not commit to it)
 *   [11] fee_payer slot           — 0x00 marker in the sender preimage;
 *                                   the 20-byte sender address in the 0x78
 *                                   handoff envelope
 *   [12] aa_authorization_list
 *   [13] sender signature         — 65-byte r||s||v envelope, appended only
 *                                   on the handoff serialization
 *
 * The sender preimage is keccak256(0x76 || rlp(items[0..12])); the handoff
 * envelope is 0x78 || rlp(items[0..13]). Both were cross-checked against the
 * ox `TxEnvelopeTempo` implementation and a live mppx credential (see
 * test/pay/tempo.test.ts for the captured vector).
 *
 * Ref: https://docs.tempo.xyz/protocol/transactions/spec-tempo-transaction
 */

export interface TempoCall {
  to: Hex;
  value: bigint;
  data: Buffer;
}

export interface TempoChargeTx {
  chainId: number;
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
  gasLimit: bigint;
  calls: TempoCall[];
  nonceKey: bigint;
  nonce: bigint;
  /** Unix seconds; required — MPP charges are always time-bounded. */
  validBefore: number;
  /** Unix seconds; TIP-1009 uses a random past value as a uniqueness salt. */
  validAfter: number;
}

/** TIP-1009 expiring-nonce lane: nonce_key = uint256 max, nonce = 0. */
export const EXPIRING_NONCE_KEY = (1n << 256n) - 1n;

const TEMPO_TYPE = 0x76;
const FEE_PAYER_MAGIC = 0x78;

function hexToBuf(h: Hex): Buffer {
  return Buffer.from(h.slice(2), 'hex');
}

function baseItems(tx: TempoChargeTx): RlpInput[] {
  return [
    encodeInt(tx.chainId),
    encodeInt(tx.maxPriorityFeePerGas),
    encodeInt(tx.maxFeePerGas),
    encodeInt(tx.gasLimit),
    tx.calls.map((c): RlpInput => [hexToBuf(c.to), encodeInt(c.value), c.data]),
    [], // access_list
    encodeInt(tx.nonceKey),
    encodeInt(tx.nonce),
    encodeInt(tx.validBefore),
    encodeInt(tx.validAfter),
  ];
}

/**
 * keccak digest the sender signs under fee sponsorship: fee_token slot empty,
 * fee-payer slot holding the single-byte 0x00 pre-sign marker.
 */
export function tempoSenderDigest(tx: TempoChargeTx): Buffer {
  const items: RlpInput[] = [
    ...baseItems(tx),
    Buffer.alloc(0), // fee_token — sender does not commit to it
    Buffer.from([0x00]), // fee payer pre-sign marker
    [], // aa_authorization_list
  ];
  return keccak256(Buffer.concat([Buffer.from([TEMPO_TYPE]), rlpEncode(items)]));
}

/**
 * Sign and serialize in the fee-payer handoff format (magic 0x78): the
 * fee-payer slot carries the sender address so the sponsor knows whose fees
 * it is covering, and the sender's 65-byte r||s||v signature envelope is
 * appended. This is the exact byte string an MPP tempo charge credential
 * carries in payload.signature.
 */
export function signTempoForFeePayer(
  tx: TempoChargeTx,
  sender: Hex,
  privateKey: Buffer | Uint8Array,
): Hex {
  const digest = tempoSenderDigest(tx);
  const sig = signDigest(digest, privateKey);
  const envelope = Buffer.concat([
    Buffer.alloc(32 - sig.r.length),
    sig.r,
    Buffer.alloc(32 - sig.s.length),
    sig.s,
    Buffer.from([27 + sig.recovery]),
  ]);
  const items: RlpInput[] = [
    ...baseItems(tx),
    Buffer.alloc(0), // fee_token — sponsor fills it in before broadcast
    hexToBuf(sender),
    [], // aa_authorization_list
    envelope,
  ];
  const encoded = Buffer.concat([Buffer.from([FEE_PAYER_MAGIC]), rlpEncode(items)]);
  return ('0x' + encoded.toString('hex')) as Hex;
}

/**
 * TIP-1009 validAfter salt: a random timestamp at least a minute in the past.
 * Two otherwise-identical expiring transactions must differ somewhere; the
 * chain treats validAfter as that discriminator.
 */
export function randomValidAfter(nowSeconds: number): number {
  const latest = nowSeconds - 60;
  if (latest <= 0) return 0;
  const r = randomBytes(8).readBigUInt64BE();
  return Number(r % BigInt(latest));
}

// ---------------------------------------------------------------------------
// TIP-20 calldata
// ---------------------------------------------------------------------------

function selector(signature: string): Buffer {
  return keccak256(Buffer.from(signature, 'utf8')).subarray(0, 4);
}

const TRANSFER = selector('transfer(address,uint256)');
const TRANSFER_WITH_MEMO = selector('transferWithMemo(address,uint256,bytes32)');

function word(v: bigint | Buffer): Buffer {
  if (Buffer.isBuffer(v)) {
    if (v.length > 32) throw new Error('word: value exceeds 32 bytes');
    return Buffer.concat([Buffer.alloc(32 - v.length), v]);
  }
  const b = encodeInt(v);
  return Buffer.concat([Buffer.alloc(32 - b.length), b]);
}

export function encodeTransfer(to: Hex, amount: bigint): Buffer {
  return Buffer.concat([TRANSFER, word(hexToBuf(to)), word(amount)]);
}

export function encodeTransferWithMemo(to: Hex, amount: bigint, memo: Hex): Buffer {
  const m = hexToBuf(memo);
  if (m.length !== 32) throw new Error('memo must be exactly 32 bytes');
  return Buffer.concat([TRANSFER_WITH_MEMO, word(hexToBuf(to)), word(amount), word(m)]);
}
