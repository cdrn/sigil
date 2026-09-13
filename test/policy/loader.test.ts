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
  equal(p.allowContractCreation, false);
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
    allow_contract_creation = true
    allow_message_signing = true
    allow_typed_data = false
  `);
  deepEqual(p.chainIds, [1, 8453, 42161]);
  // Addresses + selectors lowercased
  deepEqual(p.allowTo, ['0x000000000000000000000000000000000000dead']);
  deepEqual(p.allowedSelectors, ['0xa9059cbb', '0x095ea7b3']);
  equal(p.maxValueWei, 100000000000000000n);
  equal(p.allowContractCreation, true);
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

// ---------------------------------------------------------------------------
// require_confirm_above_wei
// ---------------------------------------------------------------------------

test('parsePolicy: require_confirm_above_wei is parsed in permissive mode', () => {
  const p = parsePolicy(`
    mode = "permissive"
    require_confirm_above_wei = "100000000000000000"
  `);
  equal(p.mode, 'permissive');
  equal(p.requireConfirmAboveWei, 100_000_000_000_000_000n);
});

test('parsePolicy: require_confirm_above_wei is parsed in strict mode', () => {
  const p = parsePolicy(`
    mode = "strict"
    chain_ids = [1]
    max_value_wei = "1000000000000000000"
    require_confirm_above_wei = "100000000000000000"
  `);
  equal(p.requireConfirmAboveWei, 100_000_000_000_000_000n);
});

test('parsePolicy: require_confirm_above_wei must be a decimal string', () => {
  throws(
    () => parsePolicy(`mode = "permissive"\nrequire_confirm_above_wei = 100`),
    /must be a decimal string/,
  );
  throws(
    () => parsePolicy(`mode = "permissive"\nrequire_confirm_above_wei = "0x10"`),
    /decimal integer string/,
  );
});

test('parsePolicy: strict mode rejects require_confirm >= max_value (confirm would never fire)', () => {
  // confirm == cap → cap denies first (value > maxValueWei), confirm never fires
  throws(
    () =>
      parsePolicy(`
        mode = "strict"
        chain_ids = [1]
        max_value_wei = "100"
        require_confirm_above_wei = "100"
      `),
    /must be less than max_value_wei/,
  );
  // confirm > cap — same problem
  throws(
    () =>
      parsePolicy(`
        mode = "strict"
        chain_ids = [1]
        max_value_wei = "100"
        require_confirm_above_wei = "200"
      `),
    /must be less than max_value_wei/,
  );
});

test('parsePolicy: strict mode allows require_confirm with max_value=0 (cap is "no value sends"; confirm gates pure-data calls? no — same field)', () => {
  // When max_value_wei=0, no value tx ever gets past the cap, so a confirm
  // threshold is decorative. We don't reject this — it's only a problem if
  // the threshold is *at or above* a nonzero cap.
  const p = parsePolicy(`
    mode = "strict"
    chain_ids = [1]
    max_value_wei = "0"
    require_confirm_above_wei = "100"
  `);
  equal(p.requireConfirmAboveWei, 100n);
});

test('parsePolicy: omitting require_confirm_above_wei leaves it undefined', () => {
  const p = parsePolicy(`mode = "permissive"`);
  equal(p.requireConfirmAboveWei, undefined);
});

test('parsePolicy: allow_message_signing / allow_typed_data must be booleans', () => {
  throws(
    () => parsePolicy(`mode = "strict"\nchain_ids = [1]\nallow_message_signing = "yes"`),
    /must be a boolean/,
  );
});

test('parsePolicy: allow_contract_creation must be a boolean', () => {
  throws(
    () => parsePolicy(`mode = "strict"\nchain_ids = [1]\nallow_contract_creation = "yes"`),
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
    try {
      r.resolve('evm:absent');
    } catch (e) {
      err = e as PolicyLoadError;
    }
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

// ---------------------------------------------------------------------------
// Rolling-window caps (mode-independent) and EIP-712 allowlists (strict)
// ---------------------------------------------------------------------------

test('parsePolicy: window caps are absent by default in both modes', () => {
  const perm = parsePolicy('mode = "permissive"\n');
  const strict = parsePolicy('mode = "strict"\nchain_ids = [1]\n');
  for (const p of [perm, strict]) {
    equal(p.maxValuePerHourWei, undefined);
    equal(p.maxValuePerDayWei, undefined);
    equal(p.svmMaxLamportsPerHour, undefined);
    equal(p.svmMaxLamportsPerDay, undefined);
  }
});

test('parsePolicy: window caps parse as bigints in permissive mode', () => {
  const p = parsePolicy(`
    mode = "permissive"
    max_value_per_hour_wei = "100000000000000000"
    max_value_per_day_wei = "1000000000000000000"
    svm_max_lamports_per_hour = "1"
    svm_max_lamports_per_day = "99999999999999999999"
  `);
  equal(p.maxValuePerHourWei, 10n ** 17n);
  equal(p.maxValuePerDayWei, 10n ** 18n);
  equal(p.svmMaxLamportsPerHour, 1n);
  equal(p.svmMaxLamportsPerDay, 99999999999999999999n);
});

test('parsePolicy: window caps parse in strict mode too', () => {
  const p = parsePolicy('mode = "strict"\nchain_ids = [1]\nmax_value_per_day_wei = "5"\n');
  equal(p.maxValuePerDayWei, 5n);
});

test('parsePolicy: window caps must be decimal strings', () => {
  throws(() => parsePolicy('mode = "permissive"\nmax_value_per_hour_wei = 5\n'), PolicyLoadError);
  throws(
    () => parsePolicy('mode = "permissive"\nmax_value_per_day_wei = "0x10"\n'),
    PolicyLoadError,
  );
  throws(
    () => parsePolicy('mode = "permissive"\nsvm_max_lamports_per_day = "-1"\n'),
    PolicyLoadError,
  );
  throws(
    () => parsePolicy('mode = "permissive"\nsvm_max_lamports_per_hour = ""\n'),
    PolicyLoadError,
  );
});

test('parsePolicy: an hourly cap above the daily cap is rejected (per asset)', () => {
  throws(
    () =>
      parsePolicy(
        'mode = "permissive"\nmax_value_per_hour_wei = "2"\nmax_value_per_day_wei = "1"\n',
      ),
    /max_value_per_hour_wei \(2\) must not exceed max_value_per_day_wei \(1\)/,
  );
  throws(
    () =>
      parsePolicy(
        'mode = "permissive"\nsvm_max_lamports_per_hour = "2"\nsvm_max_lamports_per_day = "1"\n',
      ),
    /svm_max_lamports_per_hour/,
  );
  // Equal is fine; wei vs lamports don't constrain each other.
  const p = parsePolicy(
    'mode = "permissive"\nmax_value_per_hour_wei = "3"\nmax_value_per_day_wei = "3"\nsvm_max_lamports_per_hour = "9"\n',
  );
  equal(p.maxValuePerHourWei, 3n);
  equal(p.svmMaxLamportsPerHour, 9n);
});

test('parsePolicy: typed-data allowlists default to empty in strict mode and are ignored in permissive', () => {
  const s = parsePolicy('mode = "strict"\nchain_ids = [1]\n');
  deepEqual(s.typedDataVerifyingContracts, []);
  deepEqual(s.typedDataPrimaryTypes, []);
  const p = parsePolicy('mode = "permissive"\ntyped_data_verifying_contracts = ["nonsense"]\n');
  deepEqual(p.typedDataVerifyingContracts, []);
});

test('parsePolicy: typed-data verifying contracts are validated and lowercased', () => {
  const p = parsePolicy(`
    mode = "strict"
    chain_ids = [1]
    allow_typed_data = true
    typed_data_verifying_contracts = ["0x000000000022D473030F116dDEE9F6B43aC78BA3"]
    typed_data_primary_types = ["PermitSingle", "Order"]
  `);
  deepEqual(p.typedDataVerifyingContracts, ['0x000000000022d473030f116ddee9f6b43ac78ba3']);
  deepEqual(p.typedDataPrimaryTypes, ['PermitSingle', 'Order']);
  throws(
    () =>
      parsePolicy(
        'mode = "strict"\nchain_ids = [1]\ntyped_data_verifying_contracts = ["0x1234"]\n',
      ),
    /typed_data_verifying_contracts\[0\] must be 0x-prefixed 20-byte address/,
  );
  throws(
    () => parsePolicy('mode = "strict"\nchain_ids = [1]\ntyped_data_primary_types = [" "]\n'),
    /typed_data_primary_types\[0\] must be a non-empty string/,
  );
  throws(
    () => parsePolicy('mode = "strict"\nchain_ids = [1]\ntyped_data_primary_types = "Permit"\n'),
    /must be an array/,
  );
});
