import { test } from 'node:test';
import { deepEqual, equal, ok, throws } from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  anyPolicyRequiresConfirm,
  enforceConfirmTransportPresence,
  loadConfig,
  parseConfig,
  SigilConfigError,
} from '../../src/confirm/index.js';

function tmp(): string {
  return mkdtempSync(join(tmpdir(), 'sigil-cfg-'));
}

// ---------------------------------------------------------------------------
// parseConfig
// ---------------------------------------------------------------------------

test('parseConfig: empty string → empty config', () => {
  deepEqual(parseConfig(''), {});
  deepEqual(parseConfig('   \n\n  '), {});
});

test('parseConfig: file with no [confirm] block → empty config', () => {
  deepEqual(parseConfig(`# nothing here\n`), {});
});

test('parseConfig: [confirm.ntfy] with topic only', () => {
  const c = parseConfig(`
    [confirm.ntfy]
    topic = "my-topic"
  `);
  deepEqual(c, { confirm: { ntfy: { topic: 'my-topic' } } });
});

test('parseConfig: [confirm.ntfy] with topic + server', () => {
  const c = parseConfig(`
    [confirm.ntfy]
    topic  = "t"
    server = "https://ntfy.example.com"
  `);
  deepEqual(c, { confirm: { ntfy: { topic: 't', server: 'https://ntfy.example.com' } } });
});

test('parseConfig: confirm.timeout_ms parses', () => {
  const c = parseConfig(`
    [confirm]
    timeout_ms = 90000
    [confirm.ntfy]
    topic = "t"
  `);
  equal(c.confirm?.timeoutMs, 90000);
});

test('parseConfig: missing ntfy.topic → error', () => {
  throws(
    () => parseConfig(`[confirm.ntfy]\nserver = "https://x"`),
    /topic is required/,
  );
});

test('parseConfig: ntfy.topic must be a string', () => {
  throws(
    () => parseConfig(`[confirm.ntfy]\ntopic = 123`),
    /topic is required and must be a string/,
  );
});

test('parseConfig: ntfy.server must be a string if set', () => {
  throws(
    () => parseConfig(`[confirm.ntfy]\ntopic = "t"\nserver = 42`),
    /server must be a string/,
  );
});

test('parseConfig: timeout_ms must be a positive integer', () => {
  throws(() => parseConfig(`[confirm]\ntimeout_ms = -1\n[confirm.ntfy]\ntopic="t"`), /positive integer/);
  throws(() => parseConfig(`[confirm]\ntimeout_ms = 0\n[confirm.ntfy]\ntopic="t"`), /positive integer/);
  throws(() => parseConfig(`[confirm]\ntimeout_ms = "60s"\n[confirm.ntfy]\ntopic="t"`), /positive integer/);
});

test('parseConfig: invalid TOML → SigilConfigError', () => {
  throws(() => parseConfig(`[confirm`), SigilConfigError);
});

// ---------------------------------------------------------------------------
// loadConfig
// ---------------------------------------------------------------------------

test('loadConfig: missing file → empty config (no error)', () => {
  const dir = tmp();
  try {
    deepEqual(loadConfig(join(dir, 'absent.toml')), {});
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('loadConfig: reads file from disk', () => {
  const dir = tmp();
  try {
    const path = join(dir, 'config.toml');
    writeFileSync(path, `[confirm.ntfy]\ntopic = "x"`);
    deepEqual(loadConfig(path), { confirm: { ntfy: { topic: 'x' } } });
  } finally {
    rmSync(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// anyPolicyRequiresConfirm
// ---------------------------------------------------------------------------

test('anyPolicyRequiresConfirm: missing dir → false', () => {
  equal(anyPolicyRequiresConfirm(join(tmp(), 'nope')), false);
});

test('anyPolicyRequiresConfirm: empty dir → false', () => {
  const dir = tmp();
  try {
    equal(anyPolicyRequiresConfirm(dir), false);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('anyPolicyRequiresConfirm: no policy sets confirm → false', () => {
  const dir = tmp();
  try {
    writeFileSync(join(dir, 'evm:a.toml'), `mode = "permissive"`);
    writeFileSync(join(dir, 'evm:b.toml'), `mode = "strict"\nchain_ids = [1]`);
    equal(anyPolicyRequiresConfirm(dir), false);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('anyPolicyRequiresConfirm: one policy sets confirm → true', () => {
  const dir = tmp();
  try {
    writeFileSync(join(dir, 'evm:a.toml'), `mode = "permissive"`);
    writeFileSync(
      join(dir, 'evm:b.toml'),
      `mode = "permissive"\nrequire_confirm_above_wei = "1"`,
    );
    equal(anyPolicyRequiresConfirm(dir), true);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('anyPolicyRequiresConfirm: strict allow_contract_creation → true (deploys always confirm)', () => {
  const dir = tmp();
  try {
    writeFileSync(
      join(dir, 'evm:a.toml'),
      `mode = "strict"\nchain_ids = [1]\nallow_contract_creation = true`,
    );
    equal(anyPolicyRequiresConfirm(dir), true);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('anyPolicyRequiresConfirm: permissive mode does not trip on allowContractCreation default', () => {
  // Permissive policies parse with allowContractCreation=true (deploys are
  // already allowed there, no confirm involved) — that must not force a
  // transport requirement.
  const dir = tmp();
  try {
    writeFileSync(join(dir, 'evm:a.toml'), `mode = "permissive"`);
    equal(anyPolicyRequiresConfirm(dir), false);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('anyPolicyRequiresConfirm: malformed policy file is skipped, not raised', () => {
  const dir = tmp();
  try {
    writeFileSync(join(dir, 'broken.toml'), `mode = "yolo"`);
    writeFileSync(join(dir, 'good.toml'), `mode = "permissive"`);
    // Should not throw; the malformed file is the sign-path's problem.
    equal(anyPolicyRequiresConfirm(dir), false);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('anyPolicyRequiresConfirm: non-toml files in the dir are ignored', () => {
  const dir = tmp();
  try {
    writeFileSync(join(dir, 'README.md'), 'not a policy');
    writeFileSync(join(dir, 'evm:a.toml'), `mode = "permissive"\nrequire_confirm_above_wei = "1"`);
    equal(anyPolicyRequiresConfirm(dir), true);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// enforceConfirmTransportPresence
// ---------------------------------------------------------------------------

test('enforce: no policy needs confirm → ok even without transport', () => {
  const dir = tmp();
  try {
    writeFileSync(join(dir, 'a.toml'), `mode = "permissive"`);
    enforceConfirmTransportPresence({}, dir); // no throw
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('enforce: policy needs confirm + transport configured → ok', () => {
  const dir = tmp();
  try {
    writeFileSync(join(dir, 'a.toml'), `mode = "permissive"\nrequire_confirm_above_wei = "1"`);
    enforceConfirmTransportPresence(
      { confirm: { ntfy: { topic: 't' } } },
      dir,
    );
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('enforce: policy needs confirm + no transport → throws with steering message', () => {
  const dir = tmp();
  try {
    writeFileSync(join(dir, 'a.toml'), `mode = "permissive"\nrequire_confirm_above_wei = "1"`);
    let err: SigilConfigError | null = null;
    try { enforceConfirmTransportPresence({}, dir); }
    catch (e) { err = e as SigilConfigError; }
    ok(err instanceof SigilConfigError);
    ok(/require_confirm_above_wei/.test(err!.message));
    ok(/confirm\.ntfy/.test(err!.message));
  } finally {
    rmSync(dir, { recursive: true });
  }
});
