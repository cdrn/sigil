import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import { execFile, type ChildProcess } from 'node:child_process';
import {
  appendFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DAY_MS,
  FileSpendLedger,
  HOUR_MS,
  MemorySpendLedger,
  type SpendLedger,
  type WindowCap,
} from '../../src/policy/index.js';

const T0 = 1_700_000_000_000;
const HOUR: WindowCap = { label: 'max_value_per_hour_wei', windowMs: HOUR_MS, cap: 100n };
const DAY: WindowCap = { label: 'max_value_per_day_wei', windowMs: DAY_MS, cap: 250n };

function mkTmp(): string {
  return mkdtempSync(join(tmpdir(), 'sigil-ledger-'));
}

// Shared behavioural contract, run against both implementations.
function contract(name: string, make: () => { ledger: SpendLedger; cleanup: () => void }): void {
  test(`${name}: reserve records the amount and spent() sees it`, () => {
    const { ledger, cleanup } = make();
    try {
      equal(ledger.reserve('evm:a', 'wei', 30n, [HOUR], T0), null);
      equal(ledger.spent('evm:a', 'wei', HOUR_MS, T0), 30n);
    } finally {
      cleanup();
    }
  });

  test(`${name}: a breach records nothing`, () => {
    const { ledger, cleanup } = make();
    try {
      equal(ledger.reserve('evm:a', 'wei', 90n, [HOUR], T0), null);
      const r = ledger.reserve('evm:a', 'wei', 11n, [HOUR], T0);
      ok(r !== null && /max_value_per_hour_wei/.test(r));
      equal(ledger.spent('evm:a', 'wei', HOUR_MS, T0), 90n, 'denied amount not recorded');
      equal(ledger.reserve('evm:a', 'wei', 10n, [HOUR], T0), null, 'exact remainder fits');
    } finally {
      cleanup();
    }
  });

  test(`${name}: a zero amount is a no-op success`, () => {
    const { ledger, cleanup } = make();
    try {
      equal(ledger.reserve('evm:a', 'wei', 0n, [{ ...HOUR, cap: 0n }], T0), null);
      equal(ledger.spent('evm:a', 'wei', HOUR_MS, T0), 0n);
    } finally {
      cleanup();
    }
  });

  test(`${name}: the window is half-open (now - w, now]: boundary entries`, () => {
    const { ledger, cleanup } = make();
    try {
      equal(ledger.reserve('evm:a', 'wei', 1n, [], T0), null);
      equal(ledger.spent('evm:a', 'wei', HOUR_MS, T0), 1n, 'ts === now counts');
      equal(ledger.spent('evm:a', 'wei', HOUR_MS, T0 + HOUR_MS - 1), 1n, 'just inside');
      equal(
        ledger.spent('evm:a', 'wei', HOUR_MS, T0 + HOUR_MS),
        0n,
        'exactly one window later: aged out',
      );
      equal(
        ledger.spent('evm:a', 'wei', HOUR_MS, T0 - 1),
        0n,
        'entries in the future do not count',
      );
    } finally {
      cleanup();
    }
  });

  test(`${name}: an hourly allowance refills as time passes, the daily one still binds`, () => {
    const { ledger, cleanup } = make();
    try {
      equal(ledger.reserve('evm:a', 'wei', 100n, [HOUR, DAY], T0), null);
      ok(ledger.reserve('evm:a', 'wei', 1n, [HOUR, DAY], T0 + 1) !== null, 'hour exhausted');
      equal(ledger.reserve('evm:a', 'wei', 100n, [HOUR, DAY], T0 + HOUR_MS), null, 'hour refilled');
      equal(ledger.reserve('evm:a', 'wei', 50n, [HOUR, DAY], T0 + 2 * HOUR_MS), null);
      const r = ledger.reserve('evm:a', 'wei', 1n, [HOUR, DAY], T0 + 3 * HOUR_MS);
      ok(r !== null && /max_value_per_day_wei/.test(r), 'day cap (250) now binds');
      equal(ledger.reserve('evm:a', 'wei', 1n, [HOUR, DAY], T0 + DAY_MS), null, 'day refilled');
    } finally {
      cleanup();
    }
  });

  test(`${name}: handles and assets are isolated from each other`, () => {
    const { ledger, cleanup } = make();
    try {
      equal(ledger.reserve('evm:a', 'wei', 100n, [HOUR], T0), null);
      equal(ledger.reserve('evm:b', 'wei', 100n, [HOUR], T0), null, 'other handle unaffected');
      equal(
        ledger.reserve(
          'evm:a',
          'lamports',
          100n,
          [{ ...HOUR, label: 'svm_max_lamports_per_hour' }],
          T0,
        ),
        null,
      );
      equal(ledger.spent('evm:a', 'wei', HOUR_MS, T0), 100n);
      equal(ledger.spent('evm:a', 'lamports', HOUR_MS, T0), 100n);
      equal(ledger.spent('evm:c', 'wei', HOUR_MS, T0), 0n, 'unknown handle is empty');
    } finally {
      cleanup();
    }
  });
}

contract('MemorySpendLedger', () => ({
  ledger: new MemorySpendLedger(),
  cleanup: () => undefined,
}));
contract('FileSpendLedger', () => {
  const dir = mkTmp();
  return { ledger: new FileSpendLedger(dir), cleanup: () => rmSync(dir, { recursive: true }) };
});

// --- File-specific behaviour --------------------------------------------------

test('FileSpendLedger: spends persist across instances (daemon restart)', () => {
  const dir = mkTmp();
  try {
    new FileSpendLedger(dir).reserve('evm:a', 'wei', 70n, [HOUR], T0);
    const again = new FileSpendLedger(dir);
    equal(again.spent('evm:a', 'wei', HOUR_MS, T0 + 1), 70n);
    ok(again.reserve('evm:a', 'wei', 31n, [HOUR], T0 + 1) !== null, 'cap enforced after restart');
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('FileSpendLedger: file is JSONL with decimal-string amounts, mode 0600, one per handle', () => {
  const dir = mkTmp();
  try {
    const l = new FileSpendLedger(dir);
    l.reserve('evm:a', 'wei', 10n ** 25n, [], T0);
    const path = l.pathFor('evm:a');
    equal(path, join(dir, 'evm:a.ledger'));
    equal(readFileSync(path, 'utf8'), `{"ts":${T0},"asset":"wei","amount":"${10n ** 25n}"}\n`);
    equal(statSync(path).mode & 0o777, 0o600);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('FileSpendLedger: malformed and torn lines are skipped, not fatal', () => {
  const dir = mkTmp();
  try {
    const l = new FileSpendLedger(dir);
    l.reserve('evm:a', 'wei', 5n, [], T0);
    appendFileSync(
      l.pathFor('evm:a'),
      'not json\n{"ts":"x","asset":"wei","amount":"1"}\n{"ts":1,"asset":"gold","amount":"1"}\n' +
        `{"ts":${T0},"asset":"wei","amount":"-3"}\n{"ts":${T0},"asset":"wei","amount":"7"}\n{"ts":${T0},"asset":"wei","am`,
    );
    equal(l.spent('evm:a', 'wei', HOUR_MS, T0), 12n, 'only the two valid entries count');
    equal(l.reserve('evm:a', 'wei', 1n, [HOUR], T0), null, 'still usable');
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('FileSpendLedger: a missing ledger reads as zero and is created on first reserve', () => {
  const dir = mkTmp();
  try {
    const l = new FileSpendLedger(join(dir, 'nested', 'state'));
    equal(l.spent('evm:a', 'wei', HOUR_MS, T0), 0n);
    equal(l.reserve('evm:a', 'wei', 1n, [HOUR], T0), null);
    ok(existsSync(l.pathFor('evm:a')));
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('FileSpendLedger: compaction drops entries older than a day once enough pile up', () => {
  const dir = mkTmp();
  try {
    const l = new FileSpendLedger(dir);
    const N = FileSpendLedger.COMPACT_AFTER + 5;
    for (let i = 0; i < N; i++) l.reserve('evm:a', 'wei', 1n, [], T0 + i);
    const path = l.pathFor('evm:a');
    equal(readFileSync(path, 'utf8').split('\n').filter(Boolean).length, N, 'nothing stale yet');
    // A day and a bit later: every old entry is stale; one live entry triggers the rewrite.
    const later = T0 + DAY_MS + N + 10;
    l.reserve('evm:a', 'wei', 2n, [], later - 5);
    l.reserve('evm:a', 'wei', 3n, [], later);
    const lines = readFileSync(path, 'utf8').split('\n').filter(Boolean);
    equal(lines.length, 2, 'compacted to the live tail');
    equal(l.spent('evm:a', 'wei', DAY_MS, later), 5n);
    equal(l.spent('evm:a', 'wei', DAY_MS, later - 6), 0n, 'nothing older survives');
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('FileSpendLedger: compaction keeps in-window entries even when many are stale', () => {
  const dir = mkTmp();
  try {
    const l = new FileSpendLedger(dir);
    for (let i = 0; i < FileSpendLedger.COMPACT_AFTER + 1; i++)
      l.reserve('evm:a', 'wei', 1n, [], T0);
    const later = T0 + DAY_MS + 1;
    l.reserve('evm:a', 'wei', 10n, [], later - 1000); // live
    l.reserve('evm:a', 'wei', 20n, [], later); // triggers compaction (stale > COMPACT_AFTER)
    equal(l.spent('evm:a', 'wei', DAY_MS, later), 30n);
    equal(readFileSync(l.pathFor('evm:a'), 'utf8').split('\n').filter(Boolean).length, 2);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

function awaitReady(k: ChildProcess, timeoutMs = 10_000): Promise<void> {
  return new Promise((resolve, reject) => {
    let buf = '';
    const t = setTimeout(() => reject(new Error('child never reported ready')), timeoutMs);
    k.stdout!.on('data', (d) => {
      buf += d;
      if (buf.includes('ready')) {
        clearTimeout(t);
        resolve();
      }
    });
    k.once('exit', (code) => {
      clearTimeout(t);
      reject(new Error(`child exited (${code}) before reporting ready`));
    });
  });
}

test('FileSpendLedger: barrier-released processes racing for one allowance never overspend it', async () => {
  const dir = mkTmp();
  try {
    const barrier = join(dir, 'go');
    const results = join(dir, 'results');
    const mod = fileURLToPath(new URL('../../src/policy/index.js', import.meta.url));
    const N = 4;
    const TRIES = 10;
    const CAP = 15n; // 40 attempts of 1 wei; exactly 15 may succeed
    const script = `
      import { FileSpendLedger, HOUR_MS } from ${JSON.stringify(mod)};
      import { existsSync, appendFileSync } from 'node:fs';
      const [dir, barrier, results, tries, cap] = process.argv.slice(1);
      const l = new FileSpendLedger(dir);
      const s = new Int32Array(new SharedArrayBuffer(4));
      process.stdout.write('ready\\n');
      while (!existsSync(barrier)) Atomics.wait(s, 0, 0, 1);
      const caps = [{ label: 'max_value_per_hour_wei', windowMs: HOUR_MS, cap: BigInt(cap) }];
      for (let i = 0; i < Number(tries); i++) {
        const r = l.reserve('evm:race', 'wei', 1n, caps, ${T0});
        appendFileSync(results, (r === null ? 'ok' : 'deny') + '\\n');
      }
    `;
    const kids = Array.from({ length: N }, () =>
      execFile(process.execPath, [
        '--input-type=module',
        '-e',
        script,
        dir,
        barrier,
        results,
        String(TRIES),
        String(CAP),
      ]),
    );
    const exits = kids.map(
      (k) =>
        new Promise<{ code: number | null; err: string }>((resolve) => {
          let err = '';
          k.stderr!.on('data', (d) => (err += d));
          k.once('exit', (code) => resolve({ code, err }));
        }),
    );
    try {
      await Promise.all(kids.map((k) => awaitReady(k)));
    } catch (err) {
      for (const k of kids) k.kill('SIGKILL');
      throw err;
    }
    writeFileSync(barrier, '');
    for (const r of await Promise.all(exits)) equal(r.code, 0, r.err);
    const lines = readFileSync(results, 'utf8').split('\n').filter(Boolean);
    equal(lines.length, N * TRIES);
    equal(lines.filter((l) => l === 'ok').length, Number(CAP), 'exactly the allowance succeeded');
    equal(new FileSpendLedger(dir).spent('evm:race', 'wei', HOUR_MS, T0), CAP);
  } finally {
    rmSync(dir, { recursive: true });
  }
});
