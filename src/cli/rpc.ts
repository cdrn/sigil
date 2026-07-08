import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseConfig } from '../confirm/index.js';
import { HandleTable } from '../daemon/handles.js';
import { DEFAULT_RPC_PORT } from '../rpc/index.js';
import type { SigilPaths } from './paths.js';

/**
 * `sigil rpc init <handle> --upstream <url> [--port <n>]` — provision the
 * [rpc] block that enables the JSON-RPC signing proxy, so nobody has to
 * hand-edit TOML or remember to generate a strong token.
 *
 * Config-file handling is append-only: the config file is user-owned and
 * may carry a [confirm] block and comments we must not clobber, so we never
 * parse-and-rewrite — we validate the existing content, then append the new
 * block verbatim. An existing [rpc] block is a hard refusal (edit or remove
 * it yourself), matching `sigil policy init`'s refuse-to-overwrite stance.
 */

export interface RpcInitResult {
  configPath: string;
  /** True if the config file didn't exist and was created (mode 0600). */
  created: boolean;
  portal: string;
  port: number;
  token: string;
  /** Ready-to-paste endpoint with Basic auth embedded. */
  authedUrl: string;
}

export function rpcInit(
  paths: SigilPaths,
  handle: string,
  upstream: string,
  port?: number,
): RpcInitResult {
  HandleTable.parseHandle(handle); // throws on malformed handle

  const keyfilePath = join(paths.keysDir, `${handle}.sigil`);
  if (!existsSync(keyfilePath)) {
    throw new Error(
      `rpc init: portal "${handle}" not found at ${keyfilePath} — create it first with "sigil portal new ${handle}"`,
    );
  }

  let upstreamUrl: URL;
  try {
    upstreamUrl = new URL(upstream);
  } catch {
    throw new Error(`rpc init: --upstream is not a valid URL: ${JSON.stringify(upstream)}`);
  }
  if (upstreamUrl.protocol !== 'http:' && upstreamUrl.protocol !== 'https:') {
    throw new Error(`rpc init: --upstream must be http(s), got ${upstreamUrl.protocol.replace(/:$/, '')}`);
  }
  // The URL is embedded in a TOML basic string; the characters TOML would
  // interpret can't appear in a sane RPC URL, so reject rather than escape.
  if (/["\\\n\r]/.test(upstream)) {
    throw new Error('rpc init: --upstream contains characters that cannot be written to TOML');
  }

  if (port !== undefined && (!Number.isInteger(port) || port < 1 || port > 65535)) {
    throw new Error(`rpc init: --port must be an integer in 1..65535 (got ${port})`);
  }

  let existing = '';
  let created = true;
  if (existsSync(paths.configFile)) {
    created = false;
    existing = readFileSync(paths.configFile, 'utf8');
    // Surface a malformed config now, with this command's context — not
    // later at sigil-mcp boot with a confusing indirection.
    const cfg = parseConfig(existing);
    if (cfg.rpc) {
      throw new Error(
        `rpc init: ${paths.configFile} already has an [rpc] block (portal "${cfg.rpc.portal}") — edit or remove it first`,
      );
    }
  }

  const token = randomBytes(24).toString('hex');
  const effectivePort = port ?? DEFAULT_RPC_PORT;
  const block =
    `\n# JSON-RPC signing proxy — written by "sigil rpc init". Any web3 tool can\n` +
    `# use this endpoint as an unlocked signer (see README, "JSON-RPC signing\n` +
    `# proxy"). The token is the endpoint's only credential — treat it like a\n` +
    `# password. Restart Claude Code sessions to pick up changes.\n` +
    `[rpc]\n` +
    `portal = "${handle}"\n` +
    `upstream = "${upstream}"\n` +
    `token = "${token}"\n` +
    (port !== undefined ? `port = ${port}\n` : '');

  const head = existing.length > 0 && !existing.endsWith('\n') ? existing + '\n' : existing;
  const content = head + block;
  // Belt-and-braces: never write a config sigil-mcp would refuse to parse.
  parseConfig(content);
  writeFileSync(paths.configFile, content, { mode: 0o600 });

  return {
    configPath: paths.configFile,
    created,
    portal: handle,
    port: effectivePort,
    token,
    authedUrl: `http://sigil:${token}@127.0.0.1:${effectivePort}`,
  };
}
