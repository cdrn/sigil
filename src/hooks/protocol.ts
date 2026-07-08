/**
 * Claude Code hook I/O protocol. Hooks are spawned as subprocesses; they
 * receive a JSON envelope on stdin and may write a JSON decision on stdout.
 *
 * Reference: https://docs.claude.com/en/docs/claude-code/hooks (subject to
 * change; the fields below are what sigil's hooks read and write).
 */

export interface HookEnvelope {
  session_id?: string;
  transcript_path?: string;
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  tool_response?: Record<string, unknown> | string;
  // Other fields may be present; we don't constrain them.
  [key: string]: unknown;
}

/**
 * Decision emitted by a PreToolUse hook. Returning `{ decision: "block" }`
 * stops the tool call and surfaces `reason` to the model.
 */
export interface BlockDecision {
  decision: 'block';
  reason: string;
}

/**
 * Output from a PostToolUse hook that wants to modify the tool's response
 * (e.g., redact secrets). The exact shape Claude Code accepts is in flux;
 * we emit a structure that has been stable in recent versions.
 */
export interface PostToolModification {
  hookSpecificOutput: {
    hookEventName: 'PostToolUse';
    updatedToolResponse: Record<string, unknown> | string;
  };
}

/**
 * Read the entire stdin stream and parse it as JSON. Returns an empty
 * object if stdin closes without data.
 */
export async function readHookEnvelope(
  stdin: NodeJS.ReadableStream = process.stdin,
): Promise<HookEnvelope> {
  const chunks: Buffer[] = [];
  for await (const c of stdin) {
    chunks.push(typeof c === 'string' ? Buffer.from(c, 'utf8') : (c as Buffer));
  }
  const text = Buffer.concat(chunks).toString('utf8').trim();
  if (text.length === 0) return {};
  try {
    return JSON.parse(text) as HookEnvelope;
  } catch (err) {
    throw new Error(`hook stdin was not valid JSON: ${(err as Error).message}`, { cause: err });
  }
}
