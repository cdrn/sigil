import { test } from 'node:test';
import { equal } from 'node:assert/strict';
import {
  encodeType,
  hashStruct,
  signTypedData,
  type TypedData,
  typedDataDigest,
  typeHash,
} from '../../src/eth/sign-typed.js';
import { deserializeEthSignature } from '../../src/eth/sign-message.js';
import { recoverPublicKey } from '../../src/eth/secp.js';
import { addressFromPublicKey } from '../../src/eth/address.js';

// The canonical EIP-712 example from the spec (https://eips.ethereum.org/EIPS/eip-712).
const MAIL_EXAMPLE: TypedData = {
  types: {
    Person: [
      { name: 'name', type: 'string' },
      { name: 'wallet', type: 'address' },
    ],
    Mail: [
      { name: 'from', type: 'Person' },
      { name: 'to', type: 'Person' },
      { name: 'contents', type: 'string' },
    ],
  },
  primaryType: 'Mail',
  domain: {
    name: 'Ether Mail',
    version: '1',
    chainId: 1,
    verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
  },
  message: {
    from: { name: 'Cow', wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826' },
    to: { name: 'Bob', wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB' },
    contents: 'Hello, Bob!',
  },
};

test('encodeType produces the canonical EIP-712 string for nested struct', () => {
  // Spec: "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
  equal(
    encodeType('Mail', MAIL_EXAMPLE.types),
    'Mail(Person from,Person to,string contents)Person(string name,address wallet)',
  );
});

test('typeHash(Mail) matches keccak256 of the canonical type string', () => {
  // Verified independently: keccak256("Mail(Person from,Person to,string contents)Person(string name,address wallet)")
  equal(
    typeHash('Mail', MAIL_EXAMPLE.types).toString('hex'),
    'a0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2',
  );
});

test('hashStruct(Person, ...) matches the spec value for Cow', () => {
  // Spec: hashStruct(person Cow) = 0xfc71e5fa27ff56c350aa531bc129ebdf613b772b6604664f5d8dbe21b85eb0c8
  const h = hashStruct(
    'Person',
    { name: 'Cow', wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826' },
    MAIL_EXAMPLE.types,
  );
  equal(h.toString('hex'), 'fc71e5fa27ff56c350aa531bc129ebdf613b772b6604664f5d8dbe21b85eb0c8');
});

test('typedDataDigest matches the EIP-712 spec value', () => {
  // Spec: 0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2
  equal(
    typedDataDigest(MAIL_EXAMPLE).toString('hex'),
    'be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2',
  );
});

test('signTypedData recovers to signer address', () => {
  // Use a test private key; verify recovery.
  const priv = Buffer.alloc(32);
  priv[31] = 1;
  const sig = signTypedData(MAIL_EXAMPLE, priv);
  equal(sig.length, 65);
  const parsed = deserializeEthSignature(sig);
  const pub = recoverPublicKey(typedDataDigest(MAIL_EXAMPLE), parsed);
  equal(addressFromPublicKey(pub), '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf');
});

test('different domains produce different digests for the same message', () => {
  const a = typedDataDigest(MAIL_EXAMPLE);
  const b = typedDataDigest({
    ...MAIL_EXAMPLE,
    domain: { ...MAIL_EXAMPLE.domain, chainId: 999 },
  });
  equal(a.equals(b), false);
});

test('different messages produce different digests for the same domain', () => {
  const a = typedDataDigest(MAIL_EXAMPLE);
  const b = typedDataDigest({
    ...MAIL_EXAMPLE,
    message: { ...MAIL_EXAMPLE.message, contents: 'Hello, Alice!' },
  });
  equal(a.equals(b), false);
});
