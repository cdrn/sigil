import { test } from 'node:test';
import { deepEqual, equal, ok, throws } from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  FileSystemPolicyResolver,
  parsePolicy,
  permissivePolicyResolver,
  PolicyLoadError,
} from '../../src/policy/index.js';

// ---------------------------------------------------------------------------
// parsePolicy — permissive mode
// ---------------------------------------------------------------------------

test('parsePolicy: permissive mode populates defaults that allow everything', () => {
  const p = parsePolicy(`mode = "permissive"`);
  equal(p.mode, 'permissive');
  equal(p.allowMessageSigning, true);
  equal(p.allowTypedData, true);
  // Other fields are populated but ignored by the evaluator in permissive mode.
});

test('parsePolicy: permissive mode ignores extra fields without erroring', () => {
  // Note: we don't strictly validate, but a strict mode-mismatch should still
  // not break parsing — those fields are simply unused.
  const p = parsePolicy(`
    mode = "permissive"
    chain_ids = [1]
    allow_to = []
    max_value_wei = "0"
  `);
  equal(p.mode, 'permissive');
});

// ---------------------------------------------------------------------------
// parsePolicy — strict mode required fields + defaults
// ---------------------------------------------------------------------------

test('parsePolicy: strict mode requires chain_ids', () => {
  throws(() => parsePolicy(`mode = "strict"`), /chain_ids is required/);
});

test('parsePolicy: strict mode applies sensible defaults for everything else', () => {
  const p = parsePolicy(`
    mode = "strict"
    chain_ids = [1]
  `);
  equal(p.mode, 'strict');
  deepEqual(p.chainIds, [1]);
  deepEqual(p.allowTo, []);
  equal(p.maxValueWei, 0n);
  deepEqual(p.allowedSelectors, []);
  equal(p.allowMessageSigning, false);
  equal(p.allowTypedData, false);
});

// ---------------------------------------------------------------------------
// parsePolicy — strict mode full parsing
// ---------------------------------------------------------------------------

test('parsePolicy: strict mode parses every field', () => {
  const p = parsePolicy(`
    mode = "strict"
    chain_ids = [1, 8453, 42161]
    allow_to = ["0x000000000000000000000000000000000000DEAD"]
    max_value_wei = "100000000000000000"
    allowed_selectors = ["0xA9059CBB", "0x095ea7b3"]
    allow_message_signing = true
    allow_typed_data = false
  `);
  deepEqual(p.chainIds, [1, 8453, 42161]);
  // Addresses + selectors lowercased
  deepEqual(p.allowTo, ['0x000000000000000000000000000000000000dead']);
  deepEqual(p.allowedSelectors, ['0xa9059cbb', '0x095ea7b3']);
  equal(p.maxValueWei, 100000000000000000n);
  equal(p.allowMessageSigning, true);
  equal(p.allowTypedData, false);
});

// ---------------------------------------------------------------------------
// parsePolicy — schema validation errors
// ---------------------------------------------------------------------------

test('parsePolicy: rejects bad mode', () => {
  throws(() => parsePolicy(`mode = "yolo"`), /mode must be/);
  throws(() => parsePolicy(`# no mode`), /mode must be/);
});

test('parsePolicy: rejects invalid TOML', () => {
  throws(() => parsePolicy(`mode = `), PolicyLoadError);
  throws(() => parsePolicy(`mode = "strict"\nchain_ids =`), PolicyLoadError);
});

test('parsePolicy: chain_ids must be an array of non-negative integers', () => {
  throws(() => parsePolicy(`mode = "strict"\nchain_ids = "not array"`), /must be an array/);
  throws(() => parsePolicy(`mode = "strict"\nchain_ids = [1.5]`), /non-negative integers/);
  throws(() => parsePolicy(`mode = "strict"\nchain_ids = [-1]`), /non-negative integers/);
  throws(() => parsePolicy(`mode = "strict"\nchain_ids = ["1"]`), /must be a number/);
});

test('parsePolicy: allow_to entries must be 0x + 40 hex', () => {
  throws(
    () => parsePolicy(`mode = "strict"\nchain_ids = [1]\nallow_to = ["nope"]`),
    /must be 0x-prefixed 20-byte/,
  );
  throws(
    () => parsePolicy(`mode = "strict"\nchain_ids = [1]\nallow_to = ["0x00"]`),
    /must be 0x-prefixed 20-byte/,
  );
});

test('parsePolicy: max_value_wei must be a decimal string', () => {
  throws(
    () => parsePolicy(`mode = "strict"\nchain_ids = [1]\nmax_value_wei = 100`),
    /must be a decimal string/,
  );
  throws(
    () => parsePolicy(`mode = "strict"\nchain_ids = [1]\nmax_value_wei = "0x10"`),
    /decimal integer string/,
  );
  throws(
    () => parsePolicy(`mode = "strict"\nchain_ids = [1]\nmax_value_wei = "-5"`),
    /decimal integer string/,
  );
});

test('parsePolicy: allowed_selectors must be 0x + 8 hex', () => {
  throws(
    () => parsePolicy(`mode = "strict"\nchain_ids = [1]\nallowed_selectors = ["0xa9059c"]`),
    /must be 0x \+ 4 hex bytes/,
  );
  throws(
    () => parsePolicy(`mode = "strict"\nchain_ids = [1]\nallowed_selectors = ["a9059cbb"]`),
    /must be 0x \+ 4 hex bytes/,
  );
});

test('parsePolicy: allow_message_signing / allow_typed_data must be booleans', () => {
  throws(
    () => parsePolicy(`mode = "strict"\nchain_ids = [1]\nallow_message_signing = "yes"`),
    /must be a boolean/,
  );
});

// ---------------------------------------------------------------------------
// permissivePolicyResolver
// ---------------------------------------------------------------------------

test('permissivePolicyResolver returns a permissive policy for any handle', () => {
  const r = permissivePolicyResolver();
  const p1 = r.resolve('evm:alice');
  const p2 = r.resolve('evm:bob');
  equal(p1.mode, 'permissive');
  equal(p2.mode, 'permissive');
});

// ---------------------------------------------------------------------------
// FileSystemPolicyResolver
// ---------------------------------------------------------------------------

test('FileSystemPolicyResolver: loads policy from disk', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sigil-pol-'));
  try {
    writeFileSync(join(dir, 'evm:bot.toml'), `mode = "strict"\nchain_ids = [1]\n`);
    const r = new FileSystemPolicyResolver(dir);
    const p = r.resolve('evm:bot');
    equal(p.mode, 'strict');
    deepEqual(p.chainIds, [1]);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('FileSystemPolicyResolver: missing file → PolicyLoadError with helpful message', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sigil-pol-'));
  try {
    const r = new FileSystemPolicyResolver(dir);
    let err: PolicyLoadError | null = null;
    try { r.resolve('evm:absent'); } catch (e) { err = e as PolicyLoadError; }
    ok(err instanceof PolicyLoadError);
    ok(/no policy file/.test(err!.message));
    // Error should steer users to the right command for an existing
    // portal — not "sigil portal add", which would clobber the keyfile.
    ok(/sigil policy init/.test(err!.message));
    ok(!/portal add/.test(err!.message));
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('FileSystemPolicyResolver: malformed file → PolicyLoadError', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sigil-pol-'));
  try {
    writeFileSync(join(dir, 'evm:bot.toml'), `mode = "yolo"`);
    const r = new FileSystemPolicyResolver(dir);
    throws(() => r.resolve('evm:bot'), PolicyLoadError);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('FileSystemPolicyResolver: re-read picks up edits without restart', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sigil-pol-'));
  try {
    const file = join(dir, 'evm:bot.toml');
    writeFileSync(file, `mode = "permissive"`);
    const r = new FileSystemPolicyResolver(dir);
    equal(r.resolve('evm:bot').mode, 'permissive');
    writeFileSync(file, `mode = "strict"\nchain_ids = [1]\n`);
    equal(r.resolve('evm:bot').mode, 'strict');
  } finally {
    rmSync(dir, { recursive: true });
  }
});
