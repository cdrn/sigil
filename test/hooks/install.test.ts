import { test } from 'node:test';
import { deepEqual, equal, ok } from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { installInto, settingsPath } from '../../src/hooks/install.js';

function mkTmp(): string {
  return mkdtempSync(join(tmpdir(), 'sigil-init-'));
}

test('settingsPath: project scope resolves to <root>/.claude/settings.json', () => {
  const p = settingsPath({ scope: 'project', projectRoot: '/proj' });
  equal(p, '/proj/.claude/settings.json');
});

test('settingsPath: user scope resolves to <home>/.claude/settings.json', () => {
  const p = settingsPath({ scope: 'user', homeDir: '/h' });
  equal(p, '/h/.claude/settings.json');
});

test('installInto: creates settings.json from scratch with sigil MCP + hooks', () => {
  const root = mkTmp();
  try {
    const r = installInto({ scope: 'project', projectRoot: root });
    ok(r.changed);
    const settings = JSON.parse(readFileSync(r.settingsPath, 'utf8'));
    equal(settings.mcpServers.sigil.command, 'sigil-mcp');
    ok(Array.isArray(settings.hooks.PreToolUse));
    ok(Array.isArray(settings.hooks.PostToolUse));
    // PreToolUse should match Read|Bash with sigil-hook-pre.
    const pre = settings.hooks.PreToolUse.find((m: { matcher: string }) =>
      m.matcher === 'Read|Bash',
    );
    ok(pre);
    equal(pre.hooks[0].command, 'sigil-hook-pre');
  } finally {
    rmSync(root, { recursive: true });
  }
});

test('installInto: is idempotent (second run reports no change)', () => {
  const root = mkTmp();
  try {
    const r1 = installInto({ scope: 'project', projectRoot: root });
    ok(r1.changed);
    const r2 = installInto({ scope: 'project', projectRoot: root });
    equal(r2.changed, false);
  } finally {
    rmSync(root, { recursive: true });
  }
});

test('installInto: preserves unrelated existing settings', () => {
  const root = mkTmp();
  try {
    mkdirSync(join(root, '.claude'), { recursive: true });
    const existing = {
      mcpServers: {
        otherthing: { command: '/usr/bin/other' },
      },
      theme: 'dark',
      hooks: {
        PreToolUse: [
          { matcher: 'Write', hooks: [{ type: 'command', command: '/usr/local/bin/their-hook' }] },
        ],
      },
    };
    writeFileSync(join(root, '.claude', 'settings.json'), JSON.stringify(existing, null, 2));

    const r = installInto({ scope: 'project', projectRoot: root });
    ok(r.changed);
    const after = JSON.parse(readFileSync(r.settingsPath, 'utf8'));
    // The other MCP server stays.
    equal(after.mcpServers.otherthing.command, '/usr/bin/other');
    // sigil added.
    equal(after.mcpServers.sigil.command, 'sigil-mcp');
    // Unrelated setting preserved.
    equal(after.theme, 'dark');
    // Their PreToolUse hook stayed.
    const writeMatcher = after.hooks.PreToolUse.find(
      (m: { matcher: string }) => m.matcher === 'Write',
    );
    ok(writeMatcher);
    equal(writeMatcher.hooks[0].command, '/usr/local/bin/their-hook');
  } finally {
    rmSync(root, { recursive: true });
  }
});

test('installInto: re-running replaces old sigil hook entries (no duplication)', () => {
  const root = mkTmp();
  try {
    installInto({ scope: 'project', projectRoot: root });
    installInto({ scope: 'project', projectRoot: root });
    const after = JSON.parse(readFileSync(join(root, '.claude', 'settings.json'), 'utf8'));
    // Should be exactly one sigil pre-hook, not two.
    const preSigil = after.hooks.PreToolUse.flatMap(
      (m: { hooks: { command: string }[] }) => m.hooks,
    ).filter((h: { command: string }) => h.command.includes('sigil-hook-'));
    equal(preSigil.length, 1);
  } finally {
    rmSync(root, { recursive: true });
  }
});

test('installInto: respects custom mcpCommand', () => {
  const root = mkTmp();
  try {
    installInto({
      scope: 'project',
      projectRoot: root,
      mcpCommand: '/opt/sigil/bin/sigil-mcp',
    });
    const settings = JSON.parse(readFileSync(join(root, '.claude', 'settings.json'), 'utf8'));
    equal(settings.mcpServers.sigil.command, '/opt/sigil/bin/sigil-mcp');
  } finally {
    rmSync(root, { recursive: true });
  }
});

test('installInto: user scope writes under <home>/.claude/', () => {
  const fakeHome = mkTmp();
  try {
    const r = installInto({ scope: 'user', homeDir: fakeHome });
    ok(r.changed);
    ok(existsSync(join(fakeHome, '.claude', 'settings.json')));
  } finally {
    rmSync(fakeHome, { recursive: true });
  }
});

test('installInto: malformed existing settings.json throws clearly', () => {
  const root = mkTmp();
  try {
    mkdirSync(join(root, '.claude'), { recursive: true });
    writeFileSync(join(root, '.claude', 'settings.json'), '{not valid json');
    let caught: Error | null = null;
    try { installInto({ scope: 'project', projectRoot: root }); }
    catch (e) { caught = e as Error; }
    ok(caught);
    ok(/could not parse/.test(caught!.message));
  } finally {
    rmSync(root, { recursive: true });
  }
});
