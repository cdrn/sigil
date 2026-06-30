import { keccak256 } from './keccak.js';
import { encodeInt, rlpEncode, type RlpInput } from './rlp.js';
import { signDigest } from './secp.js';

export type Hex = `0x${string}`;

export interface LegacyTx {
  type: 'legacy';
  chainId: number | bigint;
  nonce: number | bigint;
  gasPrice: number | bigint;
  gasLimit: number | bigint;
  to: Hex | null;
  value: number | bigint;
  data: Hex | Buffer;
}

export interface AccessListItem {
  address: Hex;
  storageKeys: Hex[];
}

export interface Eip1559Tx {
  type: 'eip1559';
  chainId: number | bigint;
  nonce: number | bigint;
  maxPriorityFeePerGas: number | bigint;
  maxFeePerGas: number | bigint;
  gasLimit: number | bigint;
  to: Hex | null;
  value: number | bigint;
  data: Hex | Buffer;
  accessList?: AccessListItem[];
}

export type SignableTx = LegacyTx | Eip1559Tx;

function hexToBuf(h: Hex | Buffer): Buffer {
  if (Buffer.isBuffer(h)) return h;
  const s = h.startsWith('0x') ? h.slice(2) : h;
  return Buffer.from(s, 'hex');
}

function addrToBuf(a: Hex | null): Buffer {
  if (a === null) return Buffer.alloc(0);
  return hexToBuf(a);
}

function encodeAccessList(list: AccessListItem[]): RlpInput {
  return list.map((item) => [hexToBuf(item.address), item.storageKeys.map(hexToBuf)]);
}

/**
 * RLP-encode a signature component (r or s). These arrive as fixed 32-byte buffers, but RLP integer
 * fields must be minimal big-endian with no leading zero bytes. When r or s has a high byte of 0x00
 * (~1/256 of signatures), emitting the raw 32 bytes is a non-canonical integer and nodes reject the
 * tx with "rlp: non-canonical integer (leading zero bytes)". Route through encodeInt to strip them.
 */
function encodeSigValue(buf: Buffer): Buffer {
  return encodeInt(BigInt('0x' + buf.toString('hex')));
}

/**
 * Returns the 32-byte keccak digest that should be signed for the given tx.
 * For legacy this is the EIP-155 digest; for EIP-1559 it is the type-prefixed digest.
 */
export function txDigest(tx: SignableTx): Buffer {
  if (tx.type === 'legacy') {
    // EIP-155: keccak256(rlp([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]))
    const fields: RlpInput = [
      encodeInt(tx.nonce),
      encodeInt(tx.gasPrice),
      encodeInt(tx.gasLimit),
      addrToBuf(tx.to),
      encodeInt(tx.value),
      hexToBuf(tx.data),
      encodeInt(tx.chainId),
      encodeInt(0),
      encodeInt(0),
    ];
    return keccak256(rlpEncode(fields));
  }
  // EIP-1559: keccak256(0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList]))
  const fields: RlpInput = [
    encodeInt(tx.chainId),
    encodeInt(tx.nonce),
    encodeInt(tx.maxPriorityFeePerGas),
    encodeInt(tx.maxFeePerGas),
    encodeInt(tx.gasLimit),
    addrToBuf(tx.to),
    encodeInt(tx.value),
    hexToBuf(tx.data),
    encodeAccessList(tx.accessList ?? []),
  ];
  return keccak256(Buffer.concat([Buffer.from([0x02]), rlpEncode(fields)]));
}

/**
 * Sign a transaction and return its 0x-prefixed serialized hex.
 */
export function signTransaction(tx: SignableTx, privateKey: Buffer | Uint8Array): Hex {
  const digest = txDigest(tx);
  const sig = signDigest(digest, privateKey);

  if (tx.type === 'legacy') {
    // EIP-155 v = chainId * 2 + 35 + recovery
    const chainId = typeof tx.chainId === 'bigint' ? tx.chainId : BigInt(tx.chainId);
    const v = chainId * 2n + 35n + BigInt(sig.recovery);
    const fields: RlpInput = [
      encodeInt(tx.nonce),
      encodeInt(tx.gasPrice),
      encodeInt(tx.gasLimit),
      addrToBuf(tx.to),
      encodeInt(tx.value),
      hexToBuf(tx.data),
      encodeInt(v),
      encodeSigValue(sig.r),
      encodeSigValue(sig.s),
    ];
    return ('0x' + rlpEncode(fields).toString('hex')) as Hex;
  }

  // EIP-1559: 0x02 || rlp([...txFields, yParity, r, s])
  const fields: RlpInput = [
    encodeInt(tx.chainId),
    encodeInt(tx.nonce),
    encodeInt(tx.maxPriorityFeePerGas),
    encodeInt(tx.maxFeePerGas),
    encodeInt(tx.gasLimit),
    addrToBuf(tx.to),
    encodeInt(tx.value),
    hexToBuf(tx.data),
    encodeAccessList(tx.accessList ?? []),
    encodeInt(sig.recovery),
    encodeSigValue(sig.r),
    encodeSigValue(sig.s),
  ];
  return ('0x02' + rlpEncode(fields).toString('hex')) as Hex;
}
