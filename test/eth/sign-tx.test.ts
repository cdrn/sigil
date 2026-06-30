import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import {
  type Eip1559Tx,
  type LegacyTx,
  signTransaction,
  txDigest,
} from '../../src/eth/sign-tx.js';
import { rlpDecode } from '../../src/eth/rlp.js';
import { addressFromPublicKey } from '../../src/eth/address.js';
import { recoverPublicKey, signDigest } from '../../src/eth/secp.js';

const PRIV = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex');
const ADDR = '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf';

function hexToBuf(h: string): Buffer {
  const s = h.startsWith('0x') ? h.slice(2) : h;
  return Buffer.from(s, 'hex');
}

function bufFromDecoded(d: unknown): Buffer {
  if (!Buffer.isBuffer(d)) throw new Error('expected buffer in decoded RLP');
  return d;
}

test('signTransaction for legacy tx is 0x-prefixed hex', () => {
  const tx: LegacyTx = {
    type: 'legacy',
    chainId: 1,
    nonce: 0,
    gasPrice: 20_000_000_000n,
    gasLimit: 21000n,
    to: '0x000000000000000000000000000000000000dead',
    value: 1_000_000_000_000_000_000n,
    data: '0x',
  };
  const signed = signTransaction(tx, PRIV);
  ok(signed.startsWith('0x'), 'expected 0x prefix');
  ok(signed.length > 2 + 64, 'expected non-trivial signed payload');
});

test('signed legacy tx recovers to the signer address', () => {
  const tx: LegacyTx = {
    type: 'legacy',
    chainId: 1,
    nonce: 9,
    gasPrice: 20_000_000_000n,
    gasLimit: 21000n,
    to: '0x000000000000000000000000000000000000dead',
    value: 1_000_000_000_000_000_000n,
    data: '0x',
  };
  const signed = signTransaction(tx, PRIV);
  // Parse: rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
  const decoded = rlpDecode(hexToBuf(signed));
  if (!Array.isArray(decoded)) throw new Error('expected list');
  const [, , , , , , vBuf, rBuf, sBuf] = decoded;
  const v = BigInt('0x' + bufFromDecoded(vBuf).toString('hex'));
  // EIP-155 v = chainId*2 + 35 + recovery → recovery = v - chainId*2 - 35
  const recovery = Number(v - BigInt(tx.chainId as number) * 2n - 35n) as 0 | 1;
  const pub = recoverPublicKey(txDigest(tx), {
    r: bufFromDecoded(rBuf),
    s: bufFromDecoded(sBuf),
    recovery,
  });
  equal(addressFromPublicKey(pub), ADDR);
});

test('signed EIP-1559 tx starts with 0x02 type prefix', () => {
  const tx: Eip1559Tx = {
    type: 'eip1559',
    chainId: 1,
    nonce: 0,
    maxPriorityFeePerGas: 2_000_000_000n,
    maxFeePerGas: 30_000_000_000n,
    gasLimit: 21000n,
    to: '0x000000000000000000000000000000000000dead',
    value: 100n,
    data: '0x',
  };
  const signed = signTransaction(tx, PRIV);
  ok(signed.startsWith('0x02'), `expected 0x02 prefix, got ${signed.slice(0, 4)}`);
});

test('signed EIP-1559 tx recovers to signer address', () => {
  const tx: Eip1559Tx = {
    type: 'eip1559',
    chainId: 1,
    nonce: 5,
    maxPriorityFeePerGas: 2_000_000_000n,
    maxFeePerGas: 30_000_000_000n,
    gasLimit: 21000n,
    to: '0x000000000000000000000000000000000000dead',
    value: 100n,
    data: '0xdeadbeef',
  };
  const signed = signTransaction(tx, PRIV);
  // EIP-1559: 0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, yParity, r, s])
  const payload = hexToBuf(signed).subarray(1);
  const decoded = rlpDecode(payload);
  if (!Array.isArray(decoded)) throw new Error('expected list');
  const [, , , , , , , , , yParityBuf, rBuf, sBuf] = decoded;
  const yParity = bufFromDecoded(yParityBuf).length === 0 ? 0 : bufFromDecoded(yParityBuf)[0]!;
  const pub = recoverPublicKey(txDigest(tx), {
    r: bufFromDecoded(rBuf),
    s: bufFromDecoded(sBuf),
    recovery: yParity as 0 | 1,
  });
  equal(addressFromPublicKey(pub), ADDR);
});

test('contract-creation tx (to=null) is supported', () => {
  const tx: Eip1559Tx = {
    type: 'eip1559',
    chainId: 1,
    nonce: 0,
    maxPriorityFeePerGas: 1n,
    maxFeePerGas: 1n,
    gasLimit: 100000n,
    to: null,
    value: 0n,
    data: '0x6080604052',
  };
  const signed = signTransaction(tx, PRIV);
  ok(signed.startsWith('0x02'));
  // Recover
  const payload = hexToBuf(signed).subarray(1);
  const decoded = rlpDecode(payload);
  if (!Array.isArray(decoded)) throw new Error('expected list');
  const [, , , , , toBuf, , , , yParityBuf, rBuf, sBuf] = decoded;
  // to should be empty for contract creation
  equal(bufFromDecoded(toBuf).length, 0);
  const yParity = bufFromDecoded(yParityBuf).length === 0 ? 0 : bufFromDecoded(yParityBuf)[0]!;
  const pub = recoverPublicKey(txDigest(tx), {
    r: bufFromDecoded(rBuf),
    s: bufFromDecoded(sBuf),
    recovery: yParity as 0 | 1,
  });
  equal(addressFromPublicKey(pub), ADDR);
});

// Regression: r and s arrive as fixed 32-byte buffers, but RLP integer fields must be minimal
// big-endian. When a component's high byte is 0x00 (~1/256 of signatures), emitting the raw 32
// bytes is a non-canonical integer and every Ethereum node rejects the tx with
// "rlp: non-canonical integer (leading zero bytes) ... DynamicFeeTx.R". We search nonces (RFC-6979
// signing is deterministic) for a real leading-zero case, then assert the serialized tx strips it.
test('serialized r/s are canonical when a signature component has a leading zero byte', () => {
  const base = {
    type: 'eip1559' as const,
    chainId: 11155111,
    maxPriorityFeePerGas: 1n,
    maxFeePerGas: 1n,
    gasLimit: 21000n,
    to: '0x000000000000000000000000000000000000dead' as const,
    value: 0n,
    data: '0x' as const,
  };
  let target = -1;
  for (let nonce = 0; nonce < 3000; nonce++) {
    const sig = signDigest(txDigest({ ...base, nonce }), PRIV);
    if (sig.r[0] === 0 || sig.s[0] === 0) {
      target = nonce;
      break;
    }
  }
  ok(target >= 0, 'expected a signature with a leading zero byte within 3000 nonces');

  const signed = signTransaction({ ...base, nonce: target }, PRIV);
  const decoded = rlpDecode(hexToBuf(signed).subarray(1));
  if (!Array.isArray(decoded)) throw new Error('expected list');
  const rBuf = bufFromDecoded(decoded[10]);
  const sBuf = bufFromDecoded(decoded[11]);
  ok(rBuf.length === 0 || rBuf[0] !== 0, `r must be canonical (no leading zero), got ${rBuf.toString('hex')}`);
  ok(sBuf.length === 0 || sBuf[0] !== 0, `s must be canonical (no leading zero), got ${sBuf.toString('hex')}`);
  // And it must still recover to the signer once r/s are left-padded back to 32 bytes (what a node
  // does before ecrecover) — i.e. stripping for RLP didn't lose information.
  const pad32 = (b: Buffer): Buffer => Buffer.concat([Buffer.alloc(32 - b.length), b]);
  const yParity = bufFromDecoded(decoded[9]).length === 0 ? 0 : bufFromDecoded(decoded[9])[0]!;
  const pub = recoverPublicKey(txDigest({ ...base, nonce: target }), {
    r: pad32(rBuf),
    s: pad32(sBuf),
    recovery: yParity as 0 | 1,
  });
  equal(addressFromPublicKey(pub), ADDR);
});

test('different nonces produce different signatures (so tx is bound to nonce)', () => {
  const base = {
    type: 'eip1559' as const,
    chainId: 1,
    maxPriorityFeePerGas: 1n,
    maxFeePerGas: 1n,
    gasLimit: 21000n,
    to: '0x000000000000000000000000000000000000dead' as const,
    value: 1n,
    data: '0x' as const,
  };
  const a = signTransaction({ ...base, nonce: 0 }, PRIV);
  const b = signTransaction({ ...base, nonce: 1 }, PRIV);
  ok(a !== b);
});

// External interop pin (regression for the prehash:true noble default).
//
// Earlier signDigest + recoverPublicKey both relied on noble v3's prehash
// default of true, which made the signer secretly compute sha256(digest)
// before signing. Locally everything looked fine because our recover shared
// the same default — so the in-house round-trip matched. But every Ethereum
// node (and `cast`) recovers directly from the raw keccak digest, so the
// resulting signed tx recovered to the wrong address and was rejected by
// the network with "insufficient funds" against the phantom signer.
//
// This test pins signTransaction's output against a known-good signed tx
// produced by `cast mktx` (foundry) for the same key + fields. If a future
// change reverts the prehash:false flags — or otherwise drifts from the
// canonical EIP-1559 signing — this assertion fires immediately, before
// anyone broadcasts a tx that silently recovers to a phantom signer.
//
// The private key below was historically published in a public testnet
// playground; using it here as a deterministic fixture is fine.
test('signs an EIP-1559 tx byte-identically to cast (prehash:true regression)', () => {
  const fixturePriv = Buffer.from(
    '23035b9a999c4903bf094fc7456dc59f5ee6bccad4bc43efbda5207d766b2ba7',
    'hex',
  );
  const tx: Eip1559Tx = {
    type: 'eip1559',
    chainId: 11155111,
    nonce: 0,
    maxPriorityFeePerGas: 1440000n,
    maxFeePerGas: 1962381502n,
    gasLimit: 21000n,
    to: '0x7f5b3dfb3a5dd4f5904ce397a4879fb18c22a311',
    value: 2500000000000000000n,
    data: '0x',
  };
  // Produced by `cast mktx --private-key 0x2303... <to> --value 2500000000000000000
  // --chain 11155111 --nonce 0 --priority-gas-price 1440000 --gas-price 1962381502
  // --gas-limit 21000`, verified by broadcasting to Sepolia (tx
  // 0x9d36d2215d5e8615c89c8ca2e7f40ffbf8c6e1826f372b739f01d965b13a8488).
  const expected =
    '0x02f87483aa36a7808315f9008474f790be825208947f5b3dfb3a5dd4f5904ce397a4879fb18c22a3118822b1c8c1227a000080c080a06ed6edf834d4461cdc995fcfaa5ac44252830b2cc1bd47e6106a2d93b424372fa04f4aa529d64b30a177046789658c77ecae9f0c1c5c1398018eb9ed18190cc053';
  equal(signTransaction(tx, fixturePriv), expected);
});
