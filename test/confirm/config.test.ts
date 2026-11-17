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
  throws(() => parseConfig(`[confirm.ntfy]\nserver = "https://x"`), /topic is required/);
});

test('parseConfig: ntfy.topic must be a string', () => {
  throws(
    () => parseConfig(`[confirm.ntfy]\ntopic = 123`),
    /topic is required and must be a string/,
  );
});

test('parseConfig: ntfy.server must be a string if set', () => {
  throws(() => parseConfig(`[confirm.ntfy]\ntopic = "t"\nserver = 42`), /server must be a string/);
});

test('parseConfig: timeout_ms must be a positive integer', () => {
  throws(
    () => parseConfig(`[confirm]\ntimeout_ms = -1\n[confirm.ntfy]\ntopic="t"`),
    /positive integer/,
  );
  throws(
    () => parseConfig(`[confirm]\ntimeout_ms = 0\n[confirm.ntfy]\ntopic="t"`),
    /positive integer/,
  );
  throws(
    () => parseConfig(`[confirm]\ntimeout_ms = "60s"\n[confirm.ntfy]\ntopic="t"`),
    /positive integer/,
  );
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
// [rpc] block
// ---------------------------------------------------------------------------

const RPC_OK = `
  [rpc]
  portal = "evm:bot"
  upstream = "https://sepolia.example/v3/KEY"
  token = "0123456789abcdef0123456789abcdef"
`;

test('parseConfig: [rpc] block parses with defaults', () => {
  const c = parseConfig(RPC_OK);
  equal(c.rpc!.portal, 'evm:bot');
  equal(c.rpc!.upstream, 'https://sepolia.example/v3/KEY');
  equal(c.rpc!.token, '0123456789abcdef0123456789abcdef');
  equal(c.rpc!.port, undefined);
});

test('parseConfig: [rpc] port is parsed and validated', () => {
  const c = parseConfig(RPC_OK + `port = 8545\n`);
  equal(c.rpc!.port, 8545);
  throws(() => parseConfig(RPC_OK + `port = 0\n`), /port must be an integer/);
  throws(() => parseConfig(RPC_OK + `port = 70000\n`), /port must be an integer/);
  throws(() => parseConfig(RPC_OK + `port = "8545"\n`), /port must be an integer/);
});

test('parseConfig: [rpc] portal/upstream/token are all required', () => {
  throws(
    () => parseConfig(`[rpc]\nupstream = "https://x.example"\ntoken = "0123456789abcdef"`),
    /rpc\.portal is required/,
  );
  throws(
    () => parseConfig(`[rpc]\nportal = "evm:bot"\ntoken = "0123456789abcdef"`),
    /rpc\.upstream is required/,
  );
  throws(
    () => parseConfig(`[rpc]\nportal = "evm:bot"\nupstream = "https://x.example"`),
    /rpc\.token is required/,
  );
});

test('parseConfig: [rpc] token shorter than 16 chars is rejected', () => {
  throws(
    () => parseConfig(`[rpc]\nportal = "evm:bot"\nupstream = "https://x.example"\ntoken = "short"`),
    /token must be at least 16/,
  );
});

test('parseConfig: [rpc] upstream must be an http(s) URL', () => {
  throws(
    () =>
      parseConfig(`[rpc]\nportal = "evm:bot"\nupstream = "not a url"\ntoken = "0123456789abcdef"`),
    /not a valid URL/,
  );
  throws(
    () =>
      parseConfig(
        `[rpc]\nportal = "evm:bot"\nupstream = "ws://x.example"\ntoken = "0123456789abcdef"`,
      ),
    /must be http/,
  );
});

test('parseConfig: [rpc] absent leaves config.rpc undefined', () => {
  equal(parseConfig(`[confirm.ntfy]\ntopic = "x"`).rpc, undefined);
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
    writeFileSync(join(dir, 'evm:b.toml'), `mode = "permissive"\nrequire_confirm_above_wei = "1"`);
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
    enforceConfirmTransportPresence({ confirm: { ntfy: { topic: 't' } } }, dir);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('enforce: policy needs confirm + no transport → throws with steering message', () => {
  const dir = tmp();
  try {
    writeFileSync(join(dir, 'a.toml'), `mode = "permissive"\nrequire_confirm_above_wei = "1"`);
    let err: SigilConfigError | null = null;
    try {
      enforceConfirmTransportPresence({}, dir);
    } catch (e) {
      err = e as SigilConfigError;
    }
    ok(err instanceof SigilConfigError);
    ok(/require_confirm_above_wei/.test(err!.message));
    ok(/confirm\.ntfy/.test(err!.message));
  } finally {
    rmSync(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// [simulate]
// ---------------------------------------------------------------------------

test('parseConfig: [simulate] with per-chain RPCs and a timeout', () => {
  const c = parseConfig(`
    [simulate]
    timeout_ms = 5000
    [simulate.rpc]
    1        = "https://eth.example/v3/KEY"
    11155111 = "http://127.0.0.1:8545"
  `);
  deepEqual(c.simulate, {
    timeoutMs: 5000,
    rpcByChain: new Map([
      [1n, 'https://eth.example/v3/KEY'],
      [11155111n, 'http://127.0.0.1:8545'],
    ]),
  });
});

test('parseConfig: [simulate] alone is valid; absent block leaves simulate undefined', () => {
  deepEqual(parseConfig(`[simulate]\n`).simulate, { rpcByChain: new Map() });
  equal(parseConfig(`[confirm.ntfy]\ntopic = "t"`).simulate, undefined);
  // A [simulate] block coexists with [confirm] (whose parser returns early).
  const c = parseConfig(`[confirm.ntfy]\ntopic = "t"\n[simulate.rpc]\n10 = "https://op.example"`);
  equal(c.simulate?.rpcByChain.get(10n), 'https://op.example');
  equal(c.confirm?.ntfy?.topic, 't');
});

test('parseConfig: [simulate] validation errors', () => {
  throws(() => parseConfig(`simulate = 1`), /config\.simulate must be a table/);
  throws(
    () => parseConfig(`[simulate]\ntimeout_ms = 0`),
    /config\.simulate\.timeout_ms must be a positive integer/,
  );
  throws(() => parseConfig(`[simulate]\nrpc = "x"`), /config\.simulate\.rpc must be a table/);
  throws(
    () => parseConfig(`[simulate.rpc]\nmainnet = "https://x"`),
    /key "mainnet" must be a decimal chain id/,
  );
  throws(
    () => parseConfig(`[simulate.rpc]\n1 = "https://a"\n01 = "https://b"`),
    /lists chain 1 more than once/,
  );
  throws(
    () => parseConfig(`[simulate.rpc]\n1 = 5`),
    /config\.simulate\.rpc\.1 must be a JSON-RPC URL/,
  );
  throws(() => parseConfig(`[simulate.rpc]\n1 = "not a url"`), /is not a valid URL/);
  throws(() => parseConfig(`[simulate.rpc]\n1 = "ws://node"`), /must be http\(s\), got ws/);
});
