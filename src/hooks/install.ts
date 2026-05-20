import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { homedir } from 'node:os';

/**
 * `sigil init` writes two files:
 *
 *   1. .claude/settings.json — the PreToolUse / PostToolUse ward hooks.
 *      Idempotent: re-running merges with whatever is there, preserving
 *      the user's unrelated settings.
 *
 *   2. The MCP server registration. For Claude Code CLI this lives in
 *      a *different* file than the hooks:
 *        - user scope:    ~/.claude.json        (top-level mcpServers)
 *        - project scope: <root>/.mcp.json       (top-level mcpServers)
 *
 *      The `mcpServers` key inside settings.json is read by Claude
 *      Desktop, not the CLI. Earlier versions of sigil wrote MCP config
 *      there and it was a silent no-op for CLI users. We now (a) write
 *      to the right place, and (b) strip the stale settings.json entry
 *      on every init so users running the new init recover automatically.
 */

export type InitScope = 'project' | 'user';

export interface InitOpts {
  scope: InitScope;
  /** Root for project-scoped install (where .claude/ and .mcp.json go). Defaults to CWD. */
  projectRoot?: string;
  /** Home dir for user-scoped install. Defaults to os.homedir(). */
  homeDir?: string;
  /**
   * Path to the sigil-mcp binary to register. Defaults to looking up
   * "sigil-mcp" on $PATH (which works if sigil was installed globally).
   */
  mcpCommand?: string;
}

export interface InitResult {
  settingsPath: string;
  mcpConfigPath: string;
  changed: boolean;
}

interface SettingsFile {
  mcpServers?: Record<string, McpServerConfig>;
  hooks?: HooksConfig;
  [key: string]: unknown;
}

interface McpConfigFile {
  mcpServers?: Record<string, McpServerConfig>;
  [key: string]: unknown;
}

interface McpServerConfig {
  type?: 'stdio';
  command: string;
  args?: string[];
  env?: Record<string, string>;
}

interface HookHandler {
  type: 'command';
  command: string;
}

interface HookMatcher {
  matcher: string;
  hooks: HookHandler[];
}

interface HooksConfig {
  PreToolUse?: HookMatcher[];
  PostToolUse?: HookMatcher[];
  [key: string]: HookMatcher[] | undefined;
}

const SIGIL_MCP_NAME = 'sigil';
const SIGIL_HOOK_MARKER = 'sigil-hook-';

export function settingsPath(opts: InitOpts): string {
  if (opts.scope === 'user') {
    const home = opts.homeDir ?? homedir();
    return join(home, '.claude', 'settings.json');
  }
  const root = opts.projectRoot ? resolve(opts.projectRoot) : process.cwd();
  return join(root, '.claude', 'settings.json');
}

export function mcpConfigPath(opts: InitOpts): string {
  if (opts.scope === 'user') {
    const home = opts.homeDir ?? homedir();
    return join(home, '.claude.json');
  }
  const root = opts.projectRoot ? resolve(opts.projectRoot) : process.cwd();
  return join(root, '.mcp.json');
}

/**
 * Idempotently install sigil's hook config (settings.json) + MCP server
 * registration (claude.json / .mcp.json). Existing settings and other MCP
 * servers are preserved.
 */
export function installInto(opts: InitOpts): InitResult {
  const settingsResult = installHooksInto(opts);
  const mcpResult = installMcpServerInto(opts);
  return {
    settingsPath: settingsResult.path,
    mcpConfigPath: mcpResult.path,
    changed: settingsResult.changed || mcpResult.changed,
  };
}

function installHooksInto(opts: InitOpts): { path: string; changed: boolean } {
  const path = settingsPath(opts);
  const before = readJson<SettingsFile>(path);
  const after: SettingsFile = { ...before };
  const mcpCommand = opts.mcpCommand ?? 'sigil-mcp';

  // Migration: strip any stale sigil entry from settings.json mcpServers.
  // Claude Code CLI doesn't read MCP config from here. Leaving a stale
  // entry confuses users who later run `claude mcp list` and don't see
  // it. If mcpServers becomes empty after the strip, remove the key.
  if (after.mcpServers && SIGIL_MCP_NAME in after.mcpServers) {
    const { [SIGIL_MCP_NAME]: _drop, ...rest } = after.mcpServers;
    void _drop;
    if (Object.keys(rest).length === 0) delete after.mcpServers;
    else after.mcpServers = rest;
  }

  // Hooks — remove any prior sigil entries (identified by the
  // sigil-hook- prefix in the command path) then re-add fresh ones.
  const stripSigil = (matchers: HookMatcher[] | undefined): HookMatcher[] => {
    if (!matchers) return [];
    return matchers
      .map((m) => ({
        ...m,
        hooks: m.hooks.filter((h) => !h.command.includes(SIGIL_HOOK_MARKER)),
      }))
      .filter((m) => m.hooks.length > 0);
  };

  const hooks: HooksConfig = { ...(after.hooks ?? {}) };
  hooks.PreToolUse = [
    ...stripSigil(hooks.PreToolUse),
    {
      matcher: 'Read|Bash',
      hooks: [{ type: 'command', command: 'sigil-hook-pre' }],
    },
  ];
  hooks.PostToolUse = [
    ...stripSigil(hooks.PostToolUse),
    {
      matcher: '.*',
      hooks: [{ type: 'command', command: 'sigil-hook-post' }],
    },
  ];
  after.hooks = hooks;
  void mcpCommand; // unused here — MCP server lives in the other file

  if (jsonEqual(before, after) && existsSync(path)) {
    return { path, changed: false };
  }
  writeJson(path, after);
  return { path, changed: true };
}

function installMcpServerInto(opts: InitOpts): { path: string; changed: boolean } {
  const path = mcpConfigPath(opts);
  const before = readJson<McpConfigFile>(path);
  const after: McpConfigFile = { ...before };
  const mcpCommand = opts.mcpCommand ?? 'sigil-mcp';

  const existingServers = after.mcpServers ?? {};
  after.mcpServers = {
    ...existingServers,
    [SIGIL_MCP_NAME]: {
      type: 'stdio',
      command: mcpCommand,
      args: [],
      env: {},
    },
  };

  if (jsonEqual(before, after) && existsSync(path)) {
    return { path, changed: false };
  }
  writeJson(path, after);
  return { path, changed: true };
}

function readJson<T extends object>(path: string): T {
  if (!existsSync(path)) return {} as T;
  try { statSync(path); } catch { return {} as T; }
  try {
    const text = readFileSync(path, 'utf8');
    if (text.trim() === '') return {} as T;
    return JSON.parse(text) as T;
  } catch (err) {
    throw new Error(`could not parse ${path}: ${(err as Error).message}`);
  }
}

function writeJson(path: string, obj: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(obj, null, 2) + '\n', { mode: 0o644 });
}

function jsonEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}
