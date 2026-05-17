#!/usr/bin/env node
// Walks node_modules/ and fails (exit 1) if any installed package declares
// a lifecycle script that would run at install time. This catches
// transitive deps that smuggle in install-time code execution.
//
// Note: .npmrc already has `ignore-scripts=true`, so even a flagged package
// wouldn't actually execute on `npm ci`. This script's job is to surface
// the issue at PR time so we consciously audit the new dep before it sits
// in the lockfile, where a user who disables ignore-scripts on their own
// machine would get owned.
//
// Hooks checked: preinstall, install, postinstall. These are the only
// lifecycle scripts npm runs when a CONSUMER installs sigild as a normal
// tarball-from-registry dep — the actual attack path we're defending
// against.
//
// Deliberately NOT checked:
//   - prepare / prepublish: only run on git-installs of the package and
//     during the package's own publish workflow. Not a vector for users
//     who `npm install sigild` from the registry.
//
// If you want to harden further (e.g. against users who git-install
// sigild), broaden the HOOKS list — but expect false positives like
// @iarna/toml's prepare script.

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const HOOKS = ['preinstall', 'install', 'postinstall'];

const root = process.argv[2] ?? 'node_modules';
if (!existsSync(root)) {
  console.error(`check-install-scripts: ${root} does not exist; run npm ci first`);
  process.exit(2);
}

const offenders = [];
walk(root);

if (offenders.length === 0) {
  console.log(`✓ no install scripts in dependency tree (${root})`);
  process.exit(0);
}

console.error(`✗ install scripts detected in dependency tree:\n`);
for (const o of offenders) {
  console.error(`  ${o.name}@${o.version}`);
  console.error(`    path:  ${o.path}`);
  console.error(`    hooks: ${o.hooks.map((h) => `${h}="${o.scripts[h]}"`).join(', ')}`);
  console.error('');
}
console.error('To resolve: either remove the dep, or accept the risk and add it');
console.error('to scripts/check-install-scripts.mjs ALLOWED set with a justification.');
process.exit(1);

// ---------------------------------------------------------------------------

function walk(dir) {
  let entries;
  try { entries = readdirSync(dir); } catch { return; }
  for (const name of entries) {
    if (name === '.bin' || name === '.cache' || name.startsWith('.')) continue;
    const path = join(dir, name);
    let stat;
    try { stat = statSync(path); } catch { continue; }
    if (!stat.isDirectory()) continue;

    // Scoped packages: recurse one level for child packages.
    if (name.startsWith('@')) {
      walk(path);
      continue;
    }

    const pkgPath = join(path, 'package.json');
    if (existsSync(pkgPath)) {
      let pkg;
      try { pkg = JSON.parse(readFileSync(pkgPath, 'utf8')); }
      catch { /* malformed; ignore */ continue; }
      const scripts = pkg.scripts ?? {};
      const hooks = HOOKS.filter((h) => typeof scripts[h] === 'string' && scripts[h].length > 0);
      if (hooks.length > 0) {
        offenders.push({
          name: pkg.name ?? name,
          version: pkg.version ?? '?',
          path,
          hooks,
          scripts,
        });
      }
    }

    // Nested node_modules (rare with npm's flattening, but possible).
    const nested = join(path, 'node_modules');
    if (existsSync(nested)) walk(nested);
  }
}
