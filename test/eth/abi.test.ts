import { test } from 'node:test';
import { deepEqual, equal, throws } from 'node:assert/strict';
import {
  AbiDecodeError,
  canonicalType,
  decodeAbiParameters,
  eventTopic,
  functionSelector,
  parseAbiType,
  parseSignature,
} from '../../src/eth/index.js';

/** One 32-byte word, left-padded hex (no 0x). */
function w(hex: string | number | bigint): string {
  const h = typeof hex === 'string' ? hex : hex.toString(16);
  return h.padStart(64, '0');
}
/** Right-padded word (bytes / string content). */
function r(hex: string): string {
  return hex.padEnd(Math.ceil(hex.length / 64) * 64 || 64, '0');
}
function buf(...words: string[]): Uint8Array {
  return Buffer.from(words.join(''), 'hex');
}

const A1 = '1111111111111111111111111111111111111111';
const A2 = '2222222222222222222222222222222222222222';

// ---------------------------------------------------------------------------
// selectors / topics — values cross-checked against 4byte.directory / etherscan
// ---------------------------------------------------------------------------

test('functionSelector matches well-known selectors', () => {
  equal(functionSelector('transfer(address,uint256)'), '0xa9059cbb');
  equal(functionSelector('approve(address,uint256)'), '0x095ea7b3');
  equal(functionSelector('setApprovalForAll(address,bool)'), '0xa22cb465');
  equal(
    functionSelector(
      'exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))',
    ),
    '0x414bf389',
  );
  equal(functionSelector('execute(bytes,bytes[],uint256)'), '0x3593564c');
  equal(functionSelector('Error(string)'), '0x08c379a0');
});

test('eventTopic matches the ERC-20 Transfer topic', () => {
  equal(
    eventTopic('Transfer(address,address,uint256)'),
    '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
  );
});

// ---------------------------------------------------------------------------
// type parsing
// ---------------------------------------------------------------------------

test('parseAbiType round-trips canonical strings, including nesting', () => {
  for (const t of [
    'uint256',
    'int8',
    'address',
    'bool',
    'bytes32',
    'bytes',
    'string',
    'uint256[]',
    'uint256[3]',
    'uint256[2][]',
    '(address,uint256)',
    '(address,(bytes,uint8[])[])[2]',
    '()',
  ]) {
    equal(canonicalType(parseAbiType(t)), t);
  }
  equal(canonicalType(parseAbiType('uint')), 'uint256');
  equal(canonicalType(parseAbiType('int')), 'int256');
});

test('parseAbiType rejects malformed and unsupported types', () => {
  for (const bad of [
    'uint7',
    'uint264',
    'uint0',
    'bytes0',
    'bytes33',
    'uint256[0]',
    'uint256[',
    '(address',
    'address uint',
    'fixed128x18',
    'function',
    'Uint256',
  ]) {
    throws(() => parseAbiType(bad), AbiDecodeError, bad);
  }
});

test('parseSignature splits name and inputs', () => {
  const s = parseSignature('swapExactETHForTokens(uint256,address[],address,uint256)');
  equal(s.name, 'swapExactETHForTokens');
  deepEqual(s.inputs.map(canonicalType), ['uint256', 'address[]', 'address', 'uint256']);
  equal(parseSignature('deposit()').inputs.length, 0);
  throws(() => parseSignature('no parens'), AbiDecodeError);
  throws(() => parseSignature('1bad()'), AbiDecodeError);
});

// ---------------------------------------------------------------------------
// decoding — hand-assembled vectors
// ---------------------------------------------------------------------------

test('decodes ERC-20 transfer(address,uint256) calldata args', () => {
  // a9059cbb | to | 1000
  const calldata = Buffer.from('a9059cbb' + w(A1) + w(1000), 'hex');
  const [to, amount] = decodeAbiParameters(['address', 'uint256'], calldata.subarray(4));
  equal(to, '0x' + A1);
  equal(amount, 1000n);
});

test('decodes a dynamic string', () => {
  const hello = Buffer.from('hello world').toString('hex');
  const data = buf(w(0x20), w(11), r(hello));
  deepEqual(decodeAbiParameters(['string'], data), ['hello world']);
});

test('decodes dynamic bytes alongside a static word', () => {
  // (uint256 7, bytes 0xdeadbeef)
  const data = buf(w(7), w(0x40), w(4), r('deadbeef'));
  deepEqual(decodeAbiParameters(['uint256', 'bytes'], data), [7n, '0xdeadbeef']);
});

test('decodes empty bytes and empty arrays', () => {
  deepEqual(decodeAbiParameters(['bytes'], buf(w(0x20), w(0))), ['0x']);
  deepEqual(decodeAbiParameters(['uint256[]'], buf(w(0x20), w(0))), [[]]);
});

test('decodes nested dynamic arrays uint256[][] = [[1,2],[3]]', () => {
  const data = buf(
    w(0x20), // offset of the outer array
    w(2), // outer length
    w(0x40), // elem0 offset (relative to element heads)
    w(0xa0), // elem1 offset
    w(2),
    w(1),
    w(2), // elem0 = [1,2]
    w(1),
    w(3), // elem1 = [3]
  );
  deepEqual(decodeAbiParameters(['uint256[][]'], data), [[[1n, 2n], [3n]]]);
});

test('decodes fixed arrays inline and string[] with per-element offsets', () => {
  deepEqual(decodeAbiParameters(['uint8[3]'], buf(w(1), w(2), w(3))), [[1n, 2n, 3n]]);
  const a = Buffer.from('ab').toString('hex');
  const data = buf(w(0x20), w(2), w(0x40), w(0x80), w(2), r(a), w(0), w(0));
  deepEqual(decodeAbiParameters(['string[]'], data), [['ab', '']]);
});

test('decodes Uniswap V3 exactInputSingle static tuple', () => {
  // exactInputSingle((tokenIn, tokenOut, fee, recipient, deadline, amountIn, amountOutMin, sqrtPriceLimitX96))
  const usdc = 'a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
  const weth = 'c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2';
  const calldata = Buffer.from(
    '414bf389' +
      w(usdc) +
      w(weth) +
      w(500) +
      w(A1) +
      w(1_700_000_000) +
      w(1_000_000_000) +
      w('0de0b6b3a7640000') +
      w(0),
    'hex',
  );
  const [params] = decodeAbiParameters(
    ['(address,address,uint24,address,uint256,uint256,uint256,uint160)'],
    calldata.subarray(4),
  );
  deepEqual(params, [
    '0x' + usdc,
    '0x' + weth,
    500n,
    '0x' + A1,
    1_700_000_000n,
    1_000_000_000n,
    10n ** 18n,
    0n,
  ]);
});

test('decodes a tuple with dynamic members (exactInput params)', () => {
  // exactInput((bytes path, address recipient, uint256 deadline, uint256 amountIn, uint256 amountOutMin))
  const path = A1 + '0001f4' + A2; // token, fee 500, token: 43 bytes
  const data = buf(
    w(0x20), // offset to the (dynamic) tuple
    w(0xa0), // path offset, relative to tuple start
    w(A2),
    w(99),
    w(5),
    w(4),
    w(43),
    r(path),
  );
  deepEqual(decodeAbiParameters(['(bytes,address,uint256,uint256,uint256)'], data), [
    ['0x' + path, '0x' + A2, 99n, 5n, 4n],
  ]);
});

test('decodes negative int256 / int8 via two’s complement', () => {
  deepEqual(decodeAbiParameters(['int256'], buf('f'.repeat(64))), [-1n]);
  deepEqual(decodeAbiParameters(['int8'], buf('f'.repeat(62) + '80')), [-128n]);
  deepEqual(decodeAbiParameters(['int8'], buf(w(127))), [127n]);
  deepEqual(decodeAbiParameters(['int256'], buf('8' + '0'.repeat(63))), [-(2n ** 255n)]);
});

test('decodes bool, bytesN and tolerates trailing bytes', () => {
  deepEqual(decodeAbiParameters(['bool', 'bool'], buf(w(1), w(0))), [true, false]);
  deepEqual(decodeAbiParameters(['bytes4'], buf(r('deadbeef'))), ['0xdeadbeef']);
  deepEqual(decodeAbiParameters(['uint256'], buf(w(5), w(6))), [5n]);
});

// ---------------------------------------------------------------------------
// malformed input — always AbiDecodeError, never RangeError
// ---------------------------------------------------------------------------

test('truncated calldata is an AbiDecodeError', () => {
  throws(() => decodeAbiParameters(['address', 'uint256'], buf(w(A1))), AbiDecodeError);
  throws(() => decodeAbiParameters(['uint256'], Buffer.from('00', 'hex')), AbiDecodeError);
  throws(() => decodeAbiParameters(['uint256'], new Uint8Array(0)), AbiDecodeError);
});

test('offset or length past the end is an AbiDecodeError', () => {
  throws(() => decodeAbiParameters(['bytes'], buf(w(0x40))), AbiDecodeError); // offset past end
  throws(() => decodeAbiParameters(['bytes'], buf(w(0x20), w(100))), AbiDecodeError); // length past end
  throws(() => decodeAbiParameters(['bytes'], buf('f'.repeat(64))), AbiDecodeError); // huge offset
  throws(() => decodeAbiParameters(['uint256[]'], buf(w(0x20), w(1_000_000))), AbiDecodeError);
  // Inner offset of a nested array pointing past the end.
  throws(() => decodeAbiParameters(['uint256[][]'], buf(w(0x20), w(1), w(0x1000))), AbiDecodeError);
});

test('non-canonical static encodings are rejected', () => {
  throws(() => decodeAbiParameters(['address'], buf('01' + '0'.repeat(22) + A1)), AbiDecodeError);
  throws(() => decodeAbiParameters(['bool'], buf(w(2))), AbiDecodeError);
  throws(() => decodeAbiParameters(['uint8'], buf(w(256))), AbiDecodeError);
  throws(() => decodeAbiParameters(['int8'], buf(w(0x80))), AbiDecodeError); // not sign-extended
  throws(() => decodeAbiParameters(['bytes4'], buf(r('deadbeef01'))), AbiDecodeError);
});

test('aliased offsets cannot amplify a small payload past the budget', () => {
  // bytes[] whose many elements all point at the same 2 KiB blob.
  const n = 200;
  const blobLen = 2048;
  const heads: string[] = [];
  for (let i = 0; i < n; i++) heads.push(w(n * 32));
  const data = buf(w(0x20), w(n), ...heads, w(blobLen), r('ab'.repeat(blobLen)));
  throws(() => decodeAbiParameters(['bytes[]'], data), /budget/);
});

test('array suffixes count toward the nesting limit; huge type strings are refused', () => {
  // Used to recurse once per suffix and die with a raw RangeError.
  throws(() => parseAbiType('uint256' + '[1]'.repeat(20000)), AbiDecodeError);
  throws(() => parseAbiType('uint256' + '[]'.repeat(40)), /nested too deeply/);
  throws(() => parseAbiType('(' + 'uint8,'.repeat(1000) + 'uint8)'), /longer than 4096/);
  // Mixed tuple + array nesting shares one budget.
  throws(
    () => parseAbiType('('.repeat(20) + 'uint8' + '[]'.repeat(20) + ')'.repeat(20)),
    AbiDecodeError,
  );
  // Realistic depths still parse.
  equal(canonicalType(parseAbiType('uint256' + '[]'.repeat(10))), 'uint256' + '[]'.repeat(10));
  // Error messages stay short even for long inputs.
  try {
    parseAbiType('uint256' + '[1]'.repeat(1000));
  } catch (e) {
    equal((e as Error).message.length < 200, true);
  }
});
