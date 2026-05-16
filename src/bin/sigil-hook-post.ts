#!/usr/bin/env node
import { decidePostToolUse } from '../hooks/post-tool-use.js';
import { readHookEnvelope } from '../hooks/protocol.js';

async function main(): Promise<void> {
  const env = await readHookEnvelope();
  const modification = decidePostToolUse(env);
  if (modification !== null) {
    process.stdout.write(JSON.stringify(modification) + '\n');
  }
}

main().catch((err: Error) => {
  process.stderr.write(`sigil-hook-post: ${err.message}\n`);
  process.exit(0);
});
