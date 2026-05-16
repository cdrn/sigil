import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { homedir } from 'node:os';

/**
 * `sigil init` writes the hook config + MCP server registration into
 * .claude/settings.json. Idempotent: re-running merges with whatever is
 * there, preserving the user's unrelated settings.
 */

export type InitScope = 'project' | 'user';

export interface InitOpts {
  scope: InitScope;
  /** Root for project-scoped install (where .claude/ goes). Defaults to CWD. */
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
  changed: boolean;
}

interface SettingsFile {
  mcpServers?: Record<string, McpServerConfig>;
  hooks?: HooksConfig;
  [key: string]: unknown;
}

interface McpServerConfig {
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

/**
 * Idempotently install sigil's MCP server registration + hook config.
 * Existing settings (other MCP servers, other hook handlers) are preserved.
 */
export function installInto(opts: InitOpts): InitResult {
  const path = settingsPath(opts);
  const before = readSettings(path);
  const after = { ...before };
  const mcpCommand = opts.mcpCommand ?? 'sigil-mcp';

  // 1. MCP server registration — overwrite our entry; leave others alone.
  const existingServers = after.mcpServers ?? {};
  after.mcpServers = {
    ...existingServers,
    [SIGIL_MCP_NAME]: { command: mcpCommand },
  };

  // 2. Hooks — remove any prior sigil entries (identified by the
  //    sigil-hook- prefix in the command path) then re-add fresh ones.
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

  // Bail early if no change.
  const beforeJson = JSON.stringify(before);
  const afterJson = JSON.stringify(after);
  if (beforeJson === afterJson && existsSync(path)) {
    return { settingsPath: path, changed: false };
  }

  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(after, null, 2) + '\n', { mode: 0o644 });
  return { settingsPath: path, changed: true };
}

function readSettings(path: string): SettingsFile {
  if (!existsSync(path)) return {};
  try { statSync(path); } catch { return {}; }
  try {
    const text = readFileSync(path, 'utf8');
    if (text.trim() === '') return {};
    return JSON.parse(text) as SettingsFile;
  } catch (err) {
    throw new Error(`could not parse ${path}: ${(err as Error).message}`);
  }
}
