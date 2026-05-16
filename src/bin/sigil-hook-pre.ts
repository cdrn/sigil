#!/usr/bin/env node
import { decidePreToolUse } from '../hooks/pre-tool-use.js';
import { readHookEnvelope } from '../hooks/protocol.js';

async function main(): Promise<void> {
  const env = await readHookEnvelope();
  const decision = decidePreToolUse(env);
  if (decision !== null) {
    process.stdout.write(JSON.stringify(decision) + '\n');
  }
  // No decision = allow (exit 0 with empty stdout).
}

main().catch((err: Error) => {
  // On internal failure, default to allow so we don't deadlock the agent —
  // but log loudly so the user notices something is wrong.
  process.stderr.write(`sigil-hook-pre: ${err.message}\n`);
  process.exit(0);
});
