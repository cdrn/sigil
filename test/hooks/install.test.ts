import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { installInto, mcpConfigPath, settingsPath } from '../../src/hooks/install.js';

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

test('mcpConfigPath: project scope resolves to <root>/.mcp.json', () => {
  const p = mcpConfigPath({ scope: 'project', projectRoot: '/proj' });
  equal(p, '/proj/.mcp.json');
});

test('mcpConfigPath: user scope resolves to <home>/.claude.json', () => {
  const p = mcpConfigPath({ scope: 'user', homeDir: '/h' });
  equal(p, '/h/.claude.json');
});

test('installInto: project scope writes hooks to settings.json and MCP to .mcp.json', () => {
  const root = mkTmp();
  try {
    const r = installInto({ scope: 'project', projectRoot: root });
    ok(r.changed);

    const settings = JSON.parse(readFileSync(r.settingsPath, 'utf8'));
    // Hooks landed here.
    ok(Array.isArray(settings.hooks.PreToolUse));
    ok(Array.isArray(settings.hooks.PostToolUse));
    const pre = settings.hooks.PreToolUse.find((m: { matcher: string }) =>
      m.matcher === 'Read|Bash',
    );
    ok(pre);
    equal(pre.hooks[0].command, 'sigil-hook-pre');
    // MCP did NOT land in settings.json — Claude Code CLI doesn't read it from here.
    ok(!settings.mcpServers || !('sigil' in settings.mcpServers));

    // MCP landed in the right file.
    equal(r.mcpConfigPath, join(root, '.mcp.json'));
    const mcp = JSON.parse(readFileSync(r.mcpConfigPath, 'utf8'));
    equal(mcp.mcpServers.sigil.command, 'sigil-mcp');
    equal(mcp.mcpServers.sigil.type, 'stdio');
  } finally {
    rmSync(root, { recursive: true });
  }
});

test('installInto: user scope writes MCP to <home>/.claude.json', () => {
  const fakeHome = mkTmp();
  try {
    const r = installInto({ scope: 'user', homeDir: fakeHome });
    ok(r.changed);
    equal(r.mcpConfigPath, join(fakeHome, '.claude.json'));
    const mcp = JSON.parse(readFileSync(r.mcpConfigPath, 'utf8'));
    equal(mcp.mcpServers.sigil.command, 'sigil-mcp');
    // And hooks landed in <home>/.claude/settings.json.
    ok(existsSync(join(fakeHome, '.claude', 'settings.json')));
  } finally {
    rmSync(fakeHome, { recursive: true });
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

test('installInto: preserves unrelated existing settings and other MCP servers', () => {
  const root = mkTmp();
  try {
    mkdirSync(join(root, '.claude'), { recursive: true });
    const existingSettings = {
      theme: 'dark',
      hooks: {
        PreToolUse: [
          { matcher: 'Write', hooks: [{ type: 'command', command: '/usr/local/bin/their-hook' }] },
        ],
      },
    };
    writeFileSync(join(root, '.claude', 'settings.json'), JSON.stringify(existingSettings, null, 2));
    const existingMcp = {
      mcpServers: {
        otherthing: { type: 'stdio', command: '/usr/bin/other' },
      },
    };
    writeFileSync(join(root, '.mcp.json'), JSON.stringify(existingMcp, null, 2));

    const r = installInto({ scope: 'project', projectRoot: root });
    ok(r.changed);

    const afterSettings = JSON.parse(readFileSync(r.settingsPath, 'utf8'));
    // Unrelated setting preserved.
    equal(afterSettings.theme, 'dark');
    // Their PreToolUse hook stayed.
    const writeMatcher = afterSettings.hooks.PreToolUse.find(
      (m: { matcher: string }) => m.matcher === 'Write',
    );
    ok(writeMatcher);
    equal(writeMatcher.hooks[0].command, '/usr/local/bin/their-hook');

    const afterMcp = JSON.parse(readFileSync(r.mcpConfigPath, 'utf8'));
    // The other MCP server stays.
    equal(afterMcp.mcpServers.otherthing.command, '/usr/bin/other');
    // sigil added.
    equal(afterMcp.mcpServers.sigil.command, 'sigil-mcp');
  } finally {
    rmSync(root, { recursive: true });
  }
});

test('installInto: migration — strips stale sigil entry from settings.json mcpServers', () => {
  // Simulates a user upgrading from an older sigil version that wrote
  // mcpServers.sigil into settings.json. After init, that stale entry
  // should be gone (Claude Code CLI ignored it anyway).
  const root = mkTmp();
  try {
    mkdirSync(join(root, '.claude'), { recursive: true });
    const staleSettings = {
      mcpServers: {
        sigil: { command: 'sigil-mcp' },
        otherthing: { command: '/usr/bin/other' },
      },
    };
    writeFileSync(join(root, '.claude', 'settings.json'), JSON.stringify(staleSettings, null, 2));

    installInto({ scope: 'project', projectRoot: root });

    const after = JSON.parse(readFileSync(join(root, '.claude', 'settings.json'), 'utf8'));
    // sigil entry removed from settings.json.
    ok(!('sigil' in (after.mcpServers ?? {})));
    // Other entries kept.
    equal(after.mcpServers.otherthing.command, '/usr/bin/other');
    // sigil moved to the right file.
    const mcp = JSON.parse(readFileSync(join(root, '.mcp.json'), 'utf8'));
    equal(mcp.mcpServers.sigil.command, 'sigil-mcp');
  } finally {
    rmSync(root, { recursive: true });
  }
});

test('installInto: migration — strips lone stale sigil and removes empty mcpServers key', () => {
  const root = mkTmp();
  try {
    mkdirSync(join(root, '.claude'), { recursive: true });
    const staleSettings = {
      mcpServers: { sigil: { command: 'sigil-mcp' } },
      theme: 'light',
    };
    writeFileSync(join(root, '.claude', 'settings.json'), JSON.stringify(staleSettings, null, 2));

    installInto({ scope: 'project', projectRoot: root });

    const after = JSON.parse(readFileSync(join(root, '.claude', 'settings.json'), 'utf8'));
    // mcpServers key gone entirely since it would be empty.
    ok(!('mcpServers' in after));
    equal(after.theme, 'light');
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
    const r = installInto({
      scope: 'project',
      projectRoot: root,
      mcpCommand: '/opt/sigil/bin/sigil-mcp',
    });
    const mcp = JSON.parse(readFileSync(r.mcpConfigPath, 'utf8'));
    equal(mcp.mcpServers.sigil.command, '/opt/sigil/bin/sigil-mcp');
  } finally {
    rmSync(root, { recursive: true });
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

test('installInto: malformed existing .mcp.json throws clearly', () => {
  const root = mkTmp();
  try {
    writeFileSync(join(root, '.mcp.json'), '{nope');
    let caught: Error | null = null;
    try { installInto({ scope: 'project', projectRoot: root }); }
    catch (e) { caught = e as Error; }
    ok(caught);
    ok(/could not parse/.test(caught!.message));
  } finally {
    rmSync(root, { recursive: true });
  }
});
