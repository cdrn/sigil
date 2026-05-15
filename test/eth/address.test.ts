import { test } from 'node:test';
import { equal, throws } from 'node:assert/strict';
import {
  addressFromPrivateKey,
  addressFromPublicKey,
  toChecksumAddress,
} from '../../src/eth/address.js';
import { getPublicKeyUncompressed } from '../../src/eth/secp.js';

test('addressFromPrivateKey for priv=0x01 matches the canonical test address', () => {
  const priv = Buffer.alloc(32); priv[31] = 1;
  // Well-known: secp256k1 generator point → address 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
  equal(addressFromPrivateKey(priv), '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf');
});

test('addressFromPrivateKey for priv=0x02 matches the canonical test address', () => {
  const priv = Buffer.alloc(32); priv[31] = 2;
  // 2 * G → address 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF
  equal(addressFromPrivateKey(priv), '0x2b5ad5c4795c026514f8317c7a215e218dccd6cf');
});

test('addressFromPublicKey agrees with addressFromPrivateKey', () => {
  const priv = Buffer.alloc(32); priv[31] = 7;
  const pub = getPublicKeyUncompressed(priv);
  equal(addressFromPublicKey(pub), addressFromPrivateKey(priv));
});

test('addressFromPublicKey rejects wrong-length input', () => {
  throws(() => addressFromPublicKey(Buffer.alloc(33)), /expected 65-byte/);
});

test('addressFromPublicKey rejects missing 0x04 prefix', () => {
  const bad = Buffer.alloc(65); bad[0] = 0x03;
  throws(() => addressFromPublicKey(bad), /0x04 prefix/);
});

test('toChecksumAddress on a known EIP-55 vector', () => {
  // Canonical EIP-55 examples.
  equal(
    toChecksumAddress('0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed'),
    '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
  );
  equal(
    toChecksumAddress('0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359'),
    '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
  );
  equal(
    toChecksumAddress('0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb'),
    '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
  );
  equal(
    toChecksumAddress('0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb'),
    '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
  );
});

test('toChecksumAddress accepts mixed-case input (case-insensitive)', () => {
  equal(
    toChecksumAddress('0xD1220a0cf47c7B9be7A2e6Ba89f429762E7B9aDB'),
    '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
  );
});

test('toChecksumAddress rejects non-address input', () => {
  throws(() => toChecksumAddress('0x123'), /not a 20-byte hex address/);
  throws(() => toChecksumAddress('not-an-address'), /not a 20-byte hex address/);
});
