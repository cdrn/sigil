import { scanBashCommand } from './command-scanner.js';
import { isBlockedPath, type BlockerOpts } from './path-blocker.js';
import type { BlockDecision, HookEnvelope } from './protocol.js';

/**
 * Decide whether a PreToolUse event should be blocked. Pure function; the
 * bin entrypoint wraps this with stdin/stdout handling.
 */
export function decidePreToolUse(env: HookEnvelope, opts: BlockerOpts = {}): BlockDecision | null {
  const toolName = env.tool_name;
  const input = env.tool_input ?? {};

  if (toolName === 'Read') {
    const path = typeof input['file_path'] === 'string' ? input['file_path'] : undefined;
    if (path === undefined) return null;
    const d = isBlockedPath(path, opts);
    if (d.blocked) {
      return {
        decision: 'block',
        reason: `sigil ward: ${path} matches blocked pattern ${d.matchedPattern}. This path is on sigil's wardlist (~/.sigil/wards.toml + built-in defaults). If you need to read a file like this, edit the wardlist.`,
      };
    }
    return null;
  }

  if (toolName === 'Bash') {
    const cmd = typeof input['command'] === 'string' ? input['command'] : undefined;
    if (cmd === undefined) return null;
    const d = scanBashCommand(cmd, opts);
    if (d.blocked) {
      return {
        decision: 'block',
        reason: `sigil ward: bash command blocked — ${d.reason ?? 'matched blocked pattern'}.`,
      };
    }
    return null;
  }

  return null; // not a tool we ward
}
