// Post-build: make distributed bin entrypoints executable.
// tsc preserves shebangs but does not preserve the executable bit.
// On `npm install` the `bin` field handles the symlink + chmod, but for
// local development (`npm test`, `node dist/src/bin/sigild.js`) we want
// the file to be runnable directly.

import { chmodSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const binDir = 'dist/src/bin';
if (existsSync(binDir)) {
  for (const f of readdirSync(binDir)) {
    if (f.endsWith('.js')) chmodSync(join(binDir, f), 0o755);
  }
}
