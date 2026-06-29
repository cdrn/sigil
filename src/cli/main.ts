import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { readPassphrase } from '../daemon/passphrase.js';
import type { KdfParams } from '../crypto/index.js';
import { type InitScope, installInto } from '../hooks/install.js';
import { parsePolicy } from '../policy/index.js';
import { ArgsError, parseSubcommand } from './args.js';
import { resolvePaths } from './paths.js';
import { encode as encodeQr, renderTerminal } from '../qr/index.js';
import { policyInit, portalAdd, portalAddress, portalListFromDisk, portalNew, portalRemove } from './portal.js';
import { status } from './status.js';
import { formatResult, lock, unlock } from './unlock.js';

const USAGE = `sigil — local signing control for Claude Code

Usage:
  sigil init [--user]
  sigil status
  sigil portal new <handle> [--strict]
  sigil portal add <handle> --key-file <path> [--no-remove-source] [--strict]
  sigil portal list
  sigil portal qr <handle>
  sigil portal remove <handle>
  sigil policy show <handle>
  sigil policy init <handle> [--strict]
  sigil unlock
  sigil lock

"sigil init" writes ward hooks into .claude/settings.json and registers
the MCP server in ~/.claude.json (with --user) or <root>/.mcp.json
(project scope) — the files Claude Code CLI actually reads.
"sigil portal add" writes a permissive policy by default; pass --strict
to get a locked-down template you fill in before any sign succeeds.
"sigil policy init" provisions a policy file for an existing portal
whose policy is missing (e.g. keyfile from an older sigil version).
"sigil unlock" prompts for the passphrase and pushes it to every running
sigil-mcp session (one per Claude Code window) over their control sockets,
so a single unlock covers all open windows.
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
      if (result.changed) {
        out.write(`updated ${result.settingsPath} (hooks)\n`);
        out.write(`updated ${result.mcpConfigPath} (MCP server)\n`);
      } else {
        out.write(`already up to date:\n  hooks: ${result.settingsPath}\n  mcp:   ${result.mcpConfigPath}\n`);
      }
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
        const sessions = await unlock({ paths, passphrase });
        const { message, code } = formatResult('unlock', sessions);
        (code === 0 ? out : err).write(message + '\n');
        return { code };
      } finally {
        passphrase.fill(0);
      }
    }
    if (head === 'lock') {
      const sessions = await lock({ paths });
      const { message, code } = formatResult('lock', sessions);
      (code === 0 ? out : err).write(message + '\n');
      return { code };
    }
    if (head === 'portal') {
      const sub = parseSubcommand(rest, {
        new: {
          options: {
            'strict': { type: 'boolean' },
          },
        },
        add: {
          options: {
            'key-file': { type: 'string' },
            'no-remove-source': { type: 'boolean' },
            'strict': { type: 'boolean' },
          },
        },
        list: { options: {} },
        qr: { options: {} },
        remove: { options: {} },
      });
      if (sub.command === 'new') {
        const handle = sub.positionals[0];
        if (!handle) throw new ArgsError('portal new: missing handle');
        const policyMode: 'permissive' | 'strict' =
          sub.options['strict'] === true ? 'strict' : 'permissive';
        const passphrase = await askPassphrase();
        try {
          const { address, keyfilePath, policyPath } = portalNew(paths, {
            handle,
            passphrase,
            policyMode,
            ...(opts.kdfParams ? { kdfParams: opts.kdfParams } : {}),
          });
          out.write(`generated ${handle} (${address}) → ${keyfilePath}\n`);
          out.write(`policy: ${policyMode} → ${policyPath}\n`);
          if (policyMode === 'strict') {
            out.write(`note: strict policy denies everything until you edit ${policyPath}\n`);
          }
        } finally {
          passphrase.fill(0);
        }
        return { code: 0 };
      }
      if (sub.command === 'add') {
        const handle = sub.positionals[0];
        const keyFile = sub.options['key-file'];
        if (!handle) throw new ArgsError('portal add: missing handle');
        if (typeof keyFile !== 'string' || keyFile.length === 0) {
          throw new ArgsError('portal add: --key-file is required');
        }
        const policyMode: 'permissive' | 'strict' =
          sub.options['strict'] === true ? 'strict' : 'permissive';
        const passphrase = await askPassphrase();
        try {
          const { address, keyfilePath, policyPath } = portalAdd(paths, {
            handle,
            keyFile,
            passphrase,
            policyMode,
            ...(sub.options['no-remove-source'] === true ? { removeSource: false } : {}),
            ...(opts.kdfParams ? { kdfParams: opts.kdfParams } : {}),
          });
          out.write(`added ${handle} (${address}) → ${keyfilePath}\n`);
          out.write(`policy: ${policyMode} → ${policyPath}\n`);
          if (policyMode === 'strict') {
            out.write(`note: strict policy denies everything until you edit ${policyPath}\n`);
          }
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
            for (const p of portals) {
              out.write(`${p.handle}\n  evm: ${p.address}\n  svm: ${p.svmAddress}\n`);
            }
          }
        } finally {
          passphrase.fill(0);
        }
        return { code: 0 };
      }
      if (sub.command === 'qr') {
        const handle = sub.positionals[0];
        if (!handle) throw new ArgsError('portal qr: missing handle');
        const passphrase = await askPassphrase();
        let address: string;
        try {
          address = portalAddress(paths, handle, passphrase);
        } finally {
          passphrase.fill(0);
        }
        // Byte mode preserves the address as-is. The earlier alphanumeric
        // encoding uppercased everything, which broke wallets that validate
        // EIP-55 (those reject "0X..." and all-uppercase as invalid).
        const matrix = encodeQr(address);
        out.write(`${handle} — ${address}\n\n`);
        out.write(renderTerminal(matrix));
        out.write(`\n${handle} — ${address}\n`);
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
    if (head === 'policy') {
      const sub = parseSubcommand(rest, {
        show: { options: {} },
        init: { options: { strict: { type: 'boolean' } } },
      });
      if (sub.command === 'init') {
        const handle = sub.positionals[0];
        if (!handle) throw new ArgsError('policy init: missing handle');
        const mode: 'permissive' | 'strict' =
          sub.options['strict'] === true ? 'strict' : 'permissive';
        const result = policyInit(paths, handle, mode);
        out.write(`wrote ${mode} policy → ${result.policyPath}\n`);
        if (mode === 'strict') {
          out.write(`note: strict policy denies everything until you edit ${result.policyPath}\n`);
        }
        return { code: 0 };
      }
      if (sub.command === 'show') {
        const handle = sub.positionals[0];
        if (!handle) throw new ArgsError('policy show: missing handle');
        const policyPath = join(paths.policyDir, `${handle}.toml`);
        let source: string;
        try { source = readFileSync(policyPath, 'utf8'); }
        catch (e) {
          if ((e as NodeJS.ErrnoException).code === 'ENOENT') {
            err.write(`policy: no file at ${policyPath}\n`);
            return { code: 1 };
          }
          throw e;
        }
        // Validate by parsing — surface schema errors as exit 1.
        try { parsePolicy(source); }
        catch (e) {
          err.write(`policy: ${(e as Error).message}\n`);
          err.write(`(file at ${policyPath} is on disk but doesn't parse — fix it before signing)\n`);
          return { code: 1 };
        }
        out.write(source);
        out.write(`# ${policyPath}\n`);
        return { code: 0 };
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
