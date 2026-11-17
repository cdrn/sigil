import { test } from 'node:test';
import { deepEqual, equal, ok } from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { functionSelector } from '../../src/eth/index.js';
import { AbiRegistry } from '../../src/preview/index.js';

function withDir(fn: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), 'sigil-abi-'));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const SET_FEE = { type: 'function', name: 'setFee', inputs: [{ name: 'fee', type: 'uint24' }] };

test('AbiRegistry.empty() has nothing and no warnings', () => {
  const r = AbiRegistry.empty();
  equal(r.size, 0);
  deepEqual(r.loadWarnings, []);
  equal(r.lookup('0xa9059cbb'), undefined);
});

test('fromDir: missing directory is an empty registry without warnings', () => {
  const r = AbiRegistry.fromDir(join(tmpdir(), 'sigil-abi-does-not-exist-' + process.pid));
  equal(r.size, 0);
  deepEqual(r.loadWarnings, []);
});

test('fromDir: bare arrays and Foundry/Hardhat artifacts; non-json files ignored', () => {
  withDir((dir) => {
    writeFileSync(join(dir, 'a.json'), JSON.stringify([SET_FEE]));
    writeFileSync(
      join(dir, 'b.json'),
      JSON.stringify({
        abi: [
          { type: 'constructor', inputs: [] },
          { type: 'event', name: 'Foo', inputs: [] },
          {
            type: 'function',
            name: 'swap',
            inputs: [
              {
                name: 'p',
                type: 'tuple[]',
                components: [
                  { name: 'token', type: 'address' },
                  {
                    name: 'legs',
                    type: 'tuple',
                    components: [{ name: 'amt', type: 'uint256' }],
                  },
                ],
              },
              { name: '', type: 'bytes32' },
            ],
          },
        ],
        bytecode: '0x6080',
      }),
    );
    writeFileSync(join(dir, 'notes.txt'), 'not an abi');
    const r = AbiRegistry.fromDir(dir);
    equal(r.size, 2);
    deepEqual(r.loadWarnings, []);
    const fee = r.lookup(functionSelector('setFee(uint24)'))!;
    equal(fee.source, 'a.json');
    deepEqual(
      fee.inputs.map((i) => [i.name, i.type]),
      [['fee', 'uint24']],
    );
    const swap = r.lookup(functionSelector('swap((address,(uint256))[],bytes32)'))!;
    equal(swap.source, 'b.json');
    equal(swap.signature, 'swap((address,(uint256))[],bytes32)');
    equal(swap.inputs[1]!.name, 'arg1'); // unnamed input
  });
});

test('fromDir: malformed files are skipped with a warning, never fatal', () => {
  withDir((dir) => {
    writeFileSync(join(dir, '1-bad.json'), '{ not json');
    writeFileSync(join(dir, '2-shape.json'), JSON.stringify({ notAbi: true }));
    writeFileSync(join(dir, '3-good.json'), JSON.stringify([SET_FEE]));
    writeFileSync(
      join(dir, '4-weird.json'),
      JSON.stringify([
        { type: 'function', name: 'f', inputs: [{ name: 'x', type: 'fixed128x18' }] },
        { type: 'function', name: 'g', inputs: [{ name: 'x', type: 'tuple' }] }, // no components
        { type: 'function', name: 'ok', inputs: [] },
      ]),
    );
    const r = AbiRegistry.fromDir(dir);
    equal(r.size, 2); // setFee + ok
    deepEqual(r.loadWarnings, [
      'abi: skipped 1-bad.json: invalid JSON',
      'abi: skipped 2-shape.json: expected an ABI array or an artifact with "abi"',
      'abi: 4-weird.json: skipped 2 functions with unsupported or malformed types',
    ]);
  });
});

test('fromDir: first definition of a selector wins, in sorted filename order', () => {
  withDir((dir) => {
    const renamed = { ...SET_FEE, inputs: [{ name: 'newFee', type: 'uint24' }] };
    writeFileSync(join(dir, 'z.json'), JSON.stringify([renamed]));
    writeFileSync(join(dir, 'a.json'), JSON.stringify([SET_FEE]));
    const f = AbiRegistry.fromDir(dir).lookup(functionSelector('setFee(uint24)'))!;
    equal(f.source, 'a.json');
    equal(f.inputs[0]!.name, 'fee');
  });
});

test('fromDir: an unreadable file is a warning', { skip: process.getuid?.() === 0 }, () => {
  withDir((dir) => {
    const p = join(dir, 'locked.json');
    writeFileSync(p, JSON.stringify([SET_FEE]));
    chmodSync(p, 0o000);
    const r = AbiRegistry.fromDir(dir);
    equal(r.size, 0);
    ok(r.loadWarnings[0]!.startsWith('abi: skipped locked.json: EACCES'), r.loadWarnings[0]);
    chmodSync(p, 0o600);
    mkdirSync(join(dir, 'sub.json')); // a directory with a .json name
    const r2 = AbiRegistry.fromDir(dir);
    equal(r2.size, 1);
    ok(r2.loadWarnings[0]!.startsWith('abi: skipped sub.json: EISDIR'), r2.loadWarnings[0]);
  });
});
