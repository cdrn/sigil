import { readPassphrase } from '../daemon/passphrase.js';
import type { KdfParams } from '../crypto/index.js';
import { type InitScope, installInto } from '../hooks/install.js';
import { ArgsError, parseSubcommand } from './args.js';
import { resolvePaths } from './paths.js';
import { portalAdd, portalListFromDisk, portalRemove } from './portal.js';
import { status } from './status.js';
import { formatResult, lock, unlock } from './unlock.js';

const USAGE = `sigil — local signing control for Claude Code

Usage:
  sigil init [--user]
  sigil status
  sigil portal add <handle> --key-file <path> [--no-remove-source]
  sigil portal list
  sigil portal remove <handle>
  sigil unlock
  sigil lock

"sigil init" writes the MCP server registration + tool hooks into
.claude/settings.json (or ~/.claude/settings.json with --user).
"sigil unlock" prompts for the passphrase and pushes it to the running
sigil-mcp process (spawned by Claude Code) over the control socket.
Set SIGIL_HOME to override ~/.sigil.
`;

export interface RunCliOpts {
  argv: string[];
  /** Override the passphrase reader for tests. */
  passphrase?: () => Promise<Buffer> | Buffer;
  /** Override stdout / stderr for tests. */
  stdout?: NodeJS.WritableStream;
  stderr?: NodeJS.WritableStream;
  /** Override the home/socket paths (defaults to env-resolved). */
  env?: NodeJS.ProcessEnv;
  /**
   * Internal test-only override for the KDF cost during portal add.
   * The CLI binary never sets this. See PortalAddOpts.kdfParams.
   */
  kdfParams?: KdfParams;
}

export interface CliExit {
  code: number;
}

/**
 * Pure dispatcher: takes argv (without the node binary or script path),
 * returns an exit code. Side effects route through the injected streams
 * and passphrase reader so tests don't poke at process.stdout etc.
 */
export async function runCli(opts: RunCliOpts): Promise<CliExit> {
  const out = opts.stdout ?? process.stdout;
  const err = opts.stderr ?? process.stderr;
  const paths = resolvePaths(opts.env ?? process.env);
  const askPassphrase = opts.passphrase ?? (() => readPassphrase('sigil passphrase: '));

  if (opts.argv.length === 0 || opts.argv[0] === '--help' || opts.argv[0] === '-h') {
    out.write(USAGE);
    return { code: 0 };
  }

  try {
    const [head, ...rest] = opts.argv;
    if (head === 'init') {
      const sub = parseSubcommand(['init', ...rest], {
        init: { options: { user: { type: 'boolean' } } },
      });
      const scope: InitScope = sub.options['user'] === true ? 'user' : 'project';
      const result = installInto({ scope });
      if (result.changed) out.write(`updated ${result.settingsPath}\n`);
      else out.write(`${result.settingsPath} is already up to date\n`);
      return { code: 0 };
    }
    if (head === 'status') {
      const report = await status(paths);
      out.write(JSON.stringify(report, null, 2) + '\n');
      return { code: 0 };
    }
    if (head === 'unlock') {
      const passphrase = await askPassphrase();
      try {
        const result = await unlock({ paths, passphrase });
        const { message, code } = formatResult('unlock', result);
        (code === 0 ? out : err).write(message + '\n');
        return { code };
      } finally {
        passphrase.fill(0);
      }
    }
    if (head === 'lock') {
      const result = await lock({ paths });
      const { message, code } = formatResult('lock', result);
      (code === 0 ? out : err).write(message + '\n');
      return { code };
    }
    if (head === 'portal') {
      const sub = parseSubcommand(rest, {
        add: {
          options: {
            'key-file': { type: 'string' },
            'no-remove-source': { type: 'boolean' },
          },
        },
        list: { options: {} },
        remove: { options: {} },
      });
      if (sub.command === 'add') {
        const handle = sub.positionals[0];
        const keyFile = sub.options['key-file'];
        if (!handle) throw new ArgsError('portal add: missing handle');
        if (typeof keyFile !== 'string' || keyFile.length === 0) {
          throw new ArgsError('portal add: --key-file is required');
        }
        const passphrase = await askPassphrase();
        try {
          const { address, keyfilePath } = portalAdd(paths, {
            handle,
            keyFile,
            passphrase,
            ...(sub.options['no-remove-source'] === true ? { removeSource: false } : {}),
            ...(opts.kdfParams ? { kdfParams: opts.kdfParams } : {}),
          });
          out.write(`added ${handle} (${address}) → ${keyfilePath}\n`);
        } finally {
          passphrase.fill(0);
        }
        return { code: 0 };
      }
      if (sub.command === 'list') {
        const passphrase = await askPassphrase();
        try {
          const portals = portalListFromDisk(paths, passphrase);
          if (portals.length === 0) {
            out.write('(no portals)\n');
          } else {
            for (const p of portals) out.write(`${p.handle}\t${p.address}\n`);
          }
        } finally {
          passphrase.fill(0);
        }
        return { code: 0 };
      }
      if (sub.command === 'remove') {
        const handle = sub.positionals[0];
        if (!handle) throw new ArgsError('portal remove: missing handle');
        const result = portalRemove(paths, handle);
        if (result.removed) out.write(`removed ${handle} (${result.path})\n`);
        else out.write(`portal "${handle}" not found at ${result.path}\n`);
        return { code: result.removed ? 0 : 1 };
      }
    }
    throw new ArgsError(`unknown subcommand "${head}"`);
  } catch (e) {
    if (e instanceof ArgsError) {
      err.write(`sigil: ${e.message}\n`);
      err.write('\n' + USAGE);
      return { code: 2 };
    }
    err.write(`sigil: ${(e as Error).message}\n`);
    return { code: 1 };
  }
}
