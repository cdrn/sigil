import { test } from 'node:test';
import { equal, match, ok, throws } from 'node:assert/strict';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolvePaths } from '../../src/cli/paths.js';
import { rpcInit } from '../../src/cli/rpc.js';
import { parseConfig } from '../../src/confirm/index.js';

function mkHome(): string {
  return mkdtempSync(join(tmpdir(), 'sigil-cli-rpc-'));
}

/** rpcInit only checks keyfile existence (no decrypt), so a stub file works. */
function stubPortal(home: string, handle: string): void {
  mkdirSync(join(home, 'keys'), { recursive: true });
  writeFileSync(join(home, 'keys', `${handle}.sigil`), 'stub');
}

const UPSTREAM = 'https://sepolia.example/v3/KEY';

test('rpcInit: creates config.toml with a parseable [rpc] block and strong token', () => {
  const home = mkHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    stubPortal(home, 'evm:bot');
    const result = rpcInit(paths, 'evm:bot', UPSTREAM);
    equal(result.created, true);
    equal(result.port, 8547);
    // 24 random bytes hex-encoded — comfortably above the 16-char minimum.
    equal(result.token.length, 48);
    match(result.authedUrl, /^http:\/\/sigil:[0-9a-f]{48}@127\.0\.0\.1:8547$/);
    // The written file round-trips through the real config parser.
    const cfg = parseConfig(readFileSync(paths.configFile, 'utf8'));
    equal(cfg.rpc!.portal, 'evm:bot');
    equal(cfg.rpc!.upstream, UPSTREAM);
    equal(cfg.rpc!.token, result.token);
    equal(cfg.rpc!.port, undefined); // default port is implied, not written
    equal(statSync(paths.configFile).mode & 0o777, 0o600);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('rpcInit: explicit --port is validated and written', () => {
  const home = mkHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    stubPortal(home, 'evm:bot');
    const result = rpcInit(paths, 'evm:bot', UPSTREAM, 9000);
    equal(result.port, 9000);
    equal(parseConfig(readFileSync(paths.configFile, 'utf8')).rpc!.port, 9000);
    ok(result.authedUrl.endsWith(':9000'));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('rpcInit: appends to an existing config, preserving content and comments', () => {
  const home = mkHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    stubPortal(home, 'evm:bot');
    const existing = '# my confirm setup\n[confirm.ntfy]\ntopic = "my-topic"\n';
    writeFileSync(paths.configFile, existing);
    const result = rpcInit(paths, 'evm:bot', UPSTREAM);
    equal(result.created, false);
    const content = readFileSync(paths.configFile, 'utf8');
    ok(content.startsWith(existing), 'existing content must be preserved verbatim');
    ok(content.includes('# my confirm setup'));
    const cfg = parseConfig(content);
    equal(cfg.confirm!.ntfy!.topic, 'my-topic');
    equal(cfg.rpc!.portal, 'evm:bot');
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('rpcInit: refuses when an [rpc] block already exists', () => {
  const home = mkHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    stubPortal(home, 'evm:bot');
    rpcInit(paths, 'evm:bot', UPSTREAM);
    throws(() => rpcInit(paths, 'evm:bot', UPSTREAM), /already has an \[rpc\] block/);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('rpcInit: refuses for a portal with no keyfile on disk', () => {
  const home = mkHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    throws(() => rpcInit(paths, 'evm:absent', UPSTREAM), /not found.*portal new/);
    equal(existsSync(paths.configFile), false, 'must not write config on failure');
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('rpcInit: rejects bad handle, upstream, and port', () => {
  const home = mkHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    stubPortal(home, 'evm:bot');
    throws(() => rpcInit(paths, 'nothandle', UPSTREAM));
    throws(() => rpcInit(paths, 'evm:bot', 'not a url'), /not a valid URL/);
    throws(() => rpcInit(paths, 'evm:bot', 'ws://x.example'), /must be http/);
    throws(
      () => rpcInit(paths, 'evm:bot', 'https://x.example/"quoted'),
      /cannot be written to TOML/,
    );
    throws(() => rpcInit(paths, 'evm:bot', UPSTREAM, 0), /--port must be/);
    throws(() => rpcInit(paths, 'evm:bot', UPSTREAM, 70000), /--port must be/);
    throws(() => rpcInit(paths, 'evm:bot', UPSTREAM, 1.5), /--port must be/);
    equal(existsSync(paths.configFile), false);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('rpcInit: refuses to append to a malformed config file', () => {
  const home = mkHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    stubPortal(home, 'evm:bot');
    writeFileSync(paths.configFile, 'not = valid = toml');
    throws(() => rpcInit(paths, 'evm:bot', UPSTREAM));
    equal(readFileSync(paths.configFile, 'utf8'), 'not = valid = toml', 'file must be untouched');
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('rpcInit: two runs generate different tokens (per-init randomness)', () => {
  const home = mkHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    stubPortal(home, 'evm:bot');
    const first = rpcInit(paths, 'evm:bot', UPSTREAM);
    rmSync(paths.configFile);
    const second = rpcInit(paths, 'evm:bot', UPSTREAM);
    ok(first.token !== second.token);
  } finally {
    rmSync(home, { recursive: true });
  }
});
