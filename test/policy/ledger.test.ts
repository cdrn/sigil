import { test } from 'node:test';
import { equal, ok, throws } from 'node:assert/strict';
import { execFile, type ChildProcess } from 'node:child_process';
import {
  appendFileSync,
  chmodSync,
  mkdirSync,
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
  SpendLedgerError,
  type WindowCap,
  _ledgerTestHooks,
} from '../../src/policy/index.js';

const T0 = 1_700_000_000_000;
const HOUR: WindowCap = { label: 'max_value_per_hour_wei', windowMs: HOUR_MS, cap: 100n };
const DAY: WindowCap = { label: 'max_value_per_day_wei', windowMs: DAY_MS, cap: 250n };

function mkTmp(): string {
  return mkdtempSync(join(tmpdir(), 'sigil-ledger-'));
}

// Shared behavioural contract, run against both implementations. The
// ledger owns the clock; tests drive it through `clock.now`.
function contract(
  name: string,
  make: (clock: { now: number }) => { ledger: SpendLedger; cleanup: () => void },
): void {
  test(`${name}: reserve records the amount and spent() sees it`, () => {
    const clock = { now: T0 };
    const { ledger, cleanup } = make(clock);
    try {
      equal(ledger.reserve('evm:a', 'wei', 30n, [HOUR]), null);
      equal(ledger.spent('evm:a', 'wei', HOUR_MS), 30n);
    } finally {
      cleanup();
    }
  });

  test(`${name}: a breach records nothing`, () => {
    const clock = { now: T0 };
    const { ledger, cleanup } = make(clock);
    try {
      equal(ledger.reserve('evm:a', 'wei', 90n, [HOUR]), null);
      const r = ledger.reserve('evm:a', 'wei', 11n, [HOUR]);
      ok(r !== null && /max_value_per_hour_wei/.test(r));
      equal(ledger.spent('evm:a', 'wei', HOUR_MS), 90n, 'denied amount not recorded');
      equal(ledger.reserve('evm:a', 'wei', 10n, [HOUR]), null, 'exact remainder fits');
    } finally {
      cleanup();
    }
  });

  test(`${name}: a negative amount is refused and records nothing`, () => {
    const clock = { now: T0 };
    const { ledger, cleanup } = make(clock);
    try {
      const r = ledger.reserve('evm:a', 'wei', -1n, []);
      ok(r !== null && /negative amount/.test(r));
      equal(ledger.spent('evm:a', 'wei', HOUR_MS), 0n);
      equal(ledger.reserve('evm:a', 'wei', 1n, [HOUR]), null, 'ledger still healthy');
    } finally {
      cleanup();
    }
  });

  test(`${name}: a zero amount is a no-op success`, () => {
    const clock = { now: T0 };
    const { ledger, cleanup } = make(clock);
    try {
      equal(ledger.reserve('evm:a', 'wei', 0n, [{ ...HOUR, cap: 0n }]), null);
      equal(ledger.spent('evm:a', 'wei', HOUR_MS), 0n);
    } finally {
      cleanup();
    }
  });

  test(`${name}: the window is (now - w, now]; future-dated entries still count`, () => {
    const clock = { now: T0 };
    const { ledger, cleanup } = make(clock);
    try {
      equal(ledger.reserve('evm:a', 'wei', 1n, []), null);
      equal(ledger.spent('evm:a', 'wei', HOUR_MS), 1n, 'ts === now counts');
      clock.now = T0 + HOUR_MS - 1;
      equal(ledger.spent('evm:a', 'wei', HOUR_MS), 1n, 'just inside');
      clock.now = T0 + HOUR_MS;
      equal(ledger.spent('evm:a', 'wei', HOUR_MS), 0n, 'exactly one window later: aged out');
      // A clock that stepped back (or another process that sampled later)
      // must not make a committed spend disappear.
      clock.now = T0 - 1;
      equal(ledger.spent('evm:a', 'wei', HOUR_MS), 1n, 'entries in the future count');
    } finally {
      cleanup();
    }
  });

  test(`${name}: an hourly allowance refills as time passes, the daily one still binds`, () => {
    const clock = { now: T0 };
    const { ledger, cleanup } = make(clock);
    try {
      equal(ledger.reserve('evm:a', 'wei', 100n, [HOUR, DAY]), null);
      clock.now = T0 + 1;
      ok(ledger.reserve('evm:a', 'wei', 1n, [HOUR, DAY]) !== null, 'hour exhausted');
      clock.now = T0 + HOUR_MS;
      equal(ledger.reserve('evm:a', 'wei', 100n, [HOUR, DAY]), null, 'hour refilled');
      clock.now = T0 + 2 * HOUR_MS;
      equal(ledger.reserve('evm:a', 'wei', 50n, [HOUR, DAY]), null);
      clock.now = T0 + 3 * HOUR_MS;
      const r = ledger.reserve('evm:a', 'wei', 1n, [HOUR, DAY]);
      ok(r !== null && /max_value_per_day_wei/.test(r), 'day cap (250) now binds');
      clock.now = T0 + DAY_MS;
      equal(ledger.reserve('evm:a', 'wei', 1n, [HOUR, DAY]), null, 'day refilled');
    } finally {
      cleanup();
    }
  });

  test(`${name}: handles and assets are isolated from each other`, () => {
    const clock = { now: T0 };
    const { ledger, cleanup } = make(clock);
    try {
      equal(ledger.reserve('evm:a', 'wei', 100n, [HOUR]), null);
      equal(ledger.reserve('evm:b', 'wei', 100n, [HOUR]), null, 'other handle unaffected');
      equal(
        ledger.reserve('evm:a', 'lamports', 100n, [
          { ...HOUR, label: 'svm_max_lamports_per_hour' },
        ]),
        null,
      );
      equal(ledger.spent('evm:a', 'wei', HOUR_MS), 100n);
      equal(ledger.spent('evm:a', 'lamports', HOUR_MS), 100n);
      equal(ledger.spent('evm:c', 'wei', HOUR_MS), 0n, 'unknown handle is empty');
    } finally {
      cleanup();
    }
  });
}

contract('MemorySpendLedger', (clock) => ({
  ledger: new MemorySpendLedger({ now: () => clock.now }),
  cleanup: () => undefined,
}));
contract('FileSpendLedger', (clock) => {
  const dir = mkTmp();
  return {
    ledger: new FileSpendLedger(dir, { now: () => clock.now }),
    cleanup: () => rmSync(dir, { recursive: true }),
  };
});

// --- File-specific behaviour --------------------------------------------------

function fileLedger(dir: string, clock: { now: number }): FileSpendLedger {
  return new FileSpendLedger(dir, { now: () => clock.now });
}

test('FileSpendLedger: spends persist across instances (daemon restart)', () => {
  const dir = mkTmp();
  try {
    const clock = { now: T0 };
    fileLedger(dir, clock).reserve('evm:a', 'wei', 70n, [HOUR]);
    clock.now = T0 + 1;
    const again = fileLedger(dir, clock);
    equal(again.spent('evm:a', 'wei', HOUR_MS), 70n);
    ok(again.reserve('evm:a', 'wei', 31n, [HOUR]) !== null, 'cap enforced after restart');
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('FileSpendLedger: two processes with skewed clocks still share one allowance', () => {
  // A sampled its clock, got descheduled; B (clock ahead) took the whole
  // allowance; A must then see B's "future" spend and be denied.
  const dir = mkTmp();
  try {
    const a = fileLedger(dir, { now: T0 });
    const b = fileLedger(dir, { now: T0 + 5_000 });
    equal(b.reserve('evm:a', 'wei', 100n, [HOUR]), null);
    ok(a.reserve('evm:a', 'wei', 1n, [HOUR]) !== null, "B's later-dated spend counts for A");
    equal(a.spent('evm:a', 'wei', HOUR_MS), 100n);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('FileSpendLedger: file is JSONL with decimal-string amounts, mode 0600, one per handle', () => {
  const dir = mkTmp();
  try {
    const l = fileLedger(dir, { now: T0 });
    l.reserve('evm:a', 'wei', 10n ** 25n, []);
    const path = l.pathFor('evm:a');
    equal(path, join(dir, 'evm:a.ledger'));
    equal(readFileSync(path, 'utf8'), `{"ts":${T0},"asset":"wei","amount":"${10n ** 25n}"}\n`);
    equal(statSync(path).mode & 0o777, 0o600);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('FileSpendLedger: an unreadable line fails closed — every reserve denies, nothing is written', () => {
  const dir = mkTmp();
  try {
    const l = fileLedger(dir, { now: T0 });
    l.reserve('evm:a', 'wei', 5n, []);
    const path = l.pathFor('evm:a');
    const before = readFileSync(path, 'utf8');
    appendFileSync(path, 'not json\n');
    throws(
      () => l.spent('evm:a', 'wei', HOUR_MS),
      (e: unknown) => e instanceof SpendLedgerError && /line 2/.test((e as Error).message),
    );
    throws(() => l.reserve('evm:a', 'wei', 1n, [HOUR]), SpendLedgerError);
    throws(
      () => l.reserve('evm:a', 'wei', 1n, []),
      SpendLedgerError,
      'even with no caps: history is unknown',
    );
    equal(readFileSync(path, 'utf8'), before + 'not json\n', 'file untouched');
    // Other portals are unaffected.
    equal(l.reserve('evm:b', 'wei', 1n, [HOUR]), null);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

for (const bad of [
  '{"ts":"x","asset":"wei","amount":"1"}',
  '{"ts":1,"asset":"gold","amount":"1"}',
  `{"ts":${T0},"asset":"wei","amount":"-3"}`,
  `{"ts":${T0},"asset":"wei","amount":3}`,
  '[]',
  'null',
]) {
  test(`FileSpendLedger: rejects malformed entry ${bad}`, () => {
    const dir = mkTmp();
    try {
      const l = fileLedger(dir, { now: T0 });
      writeFileSync(l.pathFor('evm:a'), bad + '\n');
      throws(() => l.spent('evm:a', 'wei', HOUR_MS), SpendLedgerError);
    } finally {
      rmSync(dir, { recursive: true });
    }
  });
}

test('FileSpendLedger: a torn final line (crash mid-write) fails closed and is never merged into', () => {
  const dir = mkTmp();
  try {
    const l = fileLedger(dir, { now: T0 });
    l.reserve('evm:a', 'wei', 5n, []);
    const path = l.pathFor('evm:a');
    appendFileSync(path, `{"ts":${T0},"asset":"wei","am`); // no newline
    throws(() => l.reserve('evm:a', 'wei', 1n, [HOUR]), SpendLedgerError);
    // A human "repairs" by deleting the torn line; history before it is intact.
    const lines = readFileSync(path, 'utf8').split('\n');
    writeFileSync(path, lines.slice(0, -1).join('\n') + '\n');
    equal(l.spent('evm:a', 'wei', HOUR_MS), 5n);
    equal(l.reserve('evm:a', 'wei', 1n, [HOUR]), null);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('FileSpendLedger: a missing ledger reads as zero and is created on first reserve', () => {
  const dir = mkTmp();
  try {
    const l = fileLedger(join(dir, 'nested', 'state'), { now: T0 });
    equal(l.spent('evm:a', 'wei', HOUR_MS), 0n);
    equal(l.reserve('evm:a', 'wei', 1n, [HOUR]), null);
    ok(existsSync(l.pathFor('evm:a')));
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('FileSpendLedger: compaction drops entries older than a day once enough pile up', () => {
  const dir = mkTmp();
  try {
    const clock = { now: T0 };
    const l = fileLedger(dir, clock);
    const N = FileSpendLedger.COMPACT_AFTER + 5;
    for (let i = 0; i < N; i++) {
      clock.now = T0 + i;
      l.reserve('evm:a', 'wei', 1n, []);
    }
    const path = l.pathFor('evm:a');
    equal(readFileSync(path, 'utf8').split('\n').filter(Boolean).length, N, 'nothing stale yet');
    const later = T0 + DAY_MS + N + 10;
    clock.now = later - 5;
    l.reserve('evm:a', 'wei', 2n, []);
    clock.now = later;
    l.reserve('evm:a', 'wei', 3n, []);
    const lines = readFileSync(path, 'utf8').split('\n').filter(Boolean);
    equal(lines.length, 2, 'compacted to the live tail');
    equal(l.spent('evm:a', 'wei', DAY_MS), 5n);
    ok(!existsSync(`${path}.tmp`), 'temp file renamed away');
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('FileSpendLedger: compaction keeps in-window and future-dated entries', () => {
  const dir = mkTmp();
  try {
    const clock = { now: T0 };
    const l = fileLedger(dir, clock);
    for (let i = 0; i < FileSpendLedger.COMPACT_AFTER + 1; i++) l.reserve('evm:a', 'wei', 1n, []);
    const later = T0 + DAY_MS + 1;
    clock.now = later + 60_000; // a "future" entry from a fast clock
    l.reserve('evm:a', 'wei', 7n, []);
    clock.now = later - 1000;
    l.reserve('evm:a', 'wei', 10n, []);
    clock.now = later;
    l.reserve('evm:a', 'wei', 20n, []); // triggers compaction
    equal(l.spent('evm:a', 'wei', DAY_MS), 37n);
    equal(readFileSync(l.pathFor('evm:a'), 'utf8').split('\n').filter(Boolean).length, 3);
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
      // Each process runs a different clock skew so no two agree on "now".
      const skew = (process.pid % 7) * 1000;
      const l = new FileSpendLedger(dir, { now: () => ${T0} + skew });
      const s = new Int32Array(new SharedArrayBuffer(4));
      process.stdout.write('ready\\n');
      while (!existsSync(barrier)) Atomics.wait(s, 0, 0, 1);
      const caps = [{ label: 'max_value_per_hour_wei', windowMs: HOUR_MS, cap: BigInt(cap) }];
      for (let i = 0; i < Number(tries); i++) {
        const r = l.reserve('evm:race', 'wei', 1n, caps);
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
    equal(new FileSpendLedger(dir, { now: () => T0 }).spent('evm:race', 'wei', HOUR_MS), CAP);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('FileSpendLedger: a refused negative amount never creates or touches the file', () => {
  const dir = mkTmp();
  try {
    const l = fileLedger(dir, { now: T0 });
    ok(l.reserve('evm:a', 'wei', -5n, []) !== null);
    ok(!existsSync(l.pathFor('evm:a')));
  } finally {
    rmSync(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// Durability failures are never swallowed
// ---------------------------------------------------------------------------

test('FileSpendLedger: a directory fsync failure after the append refuses the spend (over-counts, never under-counts)', () => {
  const dir = mkTmp();
  try {
    const l = fileLedger(dir, { now: T0 });
    equal(l.reserve('evm:a', 'wei', 5n, [HOUR]), null);
    let calls = 0;
    _ledgerTestHooks.fsyncDir = (d) => {
      calls++;
      if (d === dir) throw Object.assign(new Error('injected EIO'), { code: 'EIO' });
    };
    try {
      throws(
        () => l.reserve('evm:a', 'wei', 7n, [HOUR]),
        (e: unknown) =>
          e instanceof SpendLedgerError && /could not make .* durable/.test((e as Error).message),
      );
    } finally {
      delete _ledgerTestHooks.fsyncDir;
    }
    ok(calls >= 1, 'the seam was exercised');
    // The entry was written before the sync failed: it counts from now on.
    equal(l.spent('evm:a', 'wei', HOUR_MS), 12n, 'refused spend still counted (safe direction)');
    equal(l.reserve('evm:a', 'wei', 1n, [HOUR]), null, 'healthy storage again → fine');
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('FileSpendLedger: a state-directory fsync failure refuses the very first spend', () => {
  const dir = mkTmp();
  try {
    const stateDir = join(dir, 'state');
    const l = fileLedger(stateDir, { now: T0 });
    _ledgerTestHooks.fsyncDir = (d) => {
      if (d === dir) throw Object.assign(new Error('injected EIO'), { code: 'EIO' }); // parent of stateDir
    };
    try {
      throws(() => l.reserve('evm:a', 'wei', 1n, []), SpendLedgerError);
      ok(!existsSync(l.pathFor('evm:a')), 'nothing written before the directory was durable');
    } finally {
      delete _ledgerTestHooks.fsyncDir;
    }
    equal(l.reserve('evm:a', 'wei', 1n, []), null);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('FileSpendLedger: durability is re-established on every append, not remembered from a failed one', () => {
  const dir = mkTmp();
  try {
    const l = fileLedger(dir, { now: T0 });
    equal(l.reserve('evm:a', 'wei', 1n, []), null);
    let seen = 0;
    _ledgerTestHooks.fsyncDir = () => {
      seen++;
    };
    try {
      l.reserve('evm:a', 'wei', 1n, []);
      l.reserve('evm:a', 'wei', 1n, []);
    } finally {
      delete _ledgerTestHooks.fsyncDir;
    }
    ok(seen >= 4, `directory synced on each append (state parent + ledger dir): ${seen}`);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// #91 — every I/O failure is a SpendLedgerError (so the sign path audits it)
// ---------------------------------------------------------------------------

test('#91: a ledger path that is a directory → SpendLedgerError from spent() and reserve()', () => {
  const dir = mkTmp();
  try {
    const l = fileLedger(dir, { now: T0 });
    mkdirSync(l.pathFor('evm:a'), { recursive: true }); // EISDIR on read/open
    throws(
      () => l.spent('evm:a', 'wei', HOUR_MS),
      (e: unknown) =>
        e instanceof SpendLedgerError && /I\/O failure \(EISDIR/.test((e as Error).message),
    );
    throws(() => l.reserve('evm:a', 'wei', 1n, [HOUR]), SpendLedgerError);
    throws(
      () => l.reserve('evm:a', 'wei', 1n, []),
      SpendLedgerError,
      'even uncapped: history unknown',
    );
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('#91: a read-only ledger file → SpendLedgerError on reserve, nothing partial written', () => {
  if (process.getuid?.() === 0) return;
  const dir = mkTmp();
  try {
    const l = fileLedger(dir, { now: T0 });
    equal(l.reserve('evm:a', 'wei', 1n, []), null);
    chmodSync(l.pathFor('evm:a'), 0o400); // append opens fail EACCES
    try {
      throws(
        () => l.reserve('evm:a', 'wei', 1n, []),
        (e: unknown) =>
          e instanceof SpendLedgerError && /I\/O failure \(EACCES/.test((e as Error).message),
      );
      equal(
        l.spent('evm:a', 'wei', HOUR_MS),
        1n,
        'reads still work; the refused spend was not recorded',
      );
    } finally {
      chmodSync(l.pathFor('evm:a'), 0o600);
    }
    equal(l.reserve('evm:a', 'wei', 1n, []), null, 'healthy again');
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('#91: a compaction whose rename target is blocked → SpendLedgerError, history intact', () => {
  const dir = mkTmp();
  try {
    const clock = { now: T0 };
    const l = fileLedger(dir, clock);
    for (let i = 0; i < FileSpendLedger.COMPACT_AFTER + 1; i++) l.reserve('evm:a', 'wei', 1n, []);
    // Occupy the temp path with a non-empty directory: openSync(tmp,'w') fails EISDIR.
    mkdirSync(`${l.pathFor('evm:a')}.tmp`, { recursive: true });
    writeFileSync(join(`${l.pathFor('evm:a')}.tmp`, 'x'), '');
    clock.now = T0 + DAY_MS + 1;
    throws(() => l.reserve('evm:a', 'wei', 5n, []), SpendLedgerError);
    clock.now = T0;
    equal(
      l.spent('evm:a', 'wei', HOUR_MS),
      BigInt(FileSpendLedger.COMPACT_AFTER + 1),
      'original file untouched',
    );
  } finally {
    rmSync(dir, { recursive: true });
  }
});
