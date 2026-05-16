#!/usr/bin/env node
import { runCli } from '../cli/main.js';

runCli({ argv: process.argv.slice(2) })
  .then((exit) => process.exit(exit.code))
  .catch((err: Error) => {
    process.stderr.write(`sigil: ${err.message}\n`);
    process.exit(1);
  });
