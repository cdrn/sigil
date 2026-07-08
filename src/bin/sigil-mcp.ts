#!/usr/bin/env node
import { chmodSync, mkdirSync } from 'node:fs';
import { AuditWriter } from '../audit/index.js';
import { resolvePaths, sessionSocketPath } from '../cli/paths.js';
import {
  ConfirmGate,
  enforceConfirmTransportPresence,
  loadConfig,
  NtfyTransport,
  startAckServer,
  type AckServer,
  type ConfirmTransport,
} from '../confirm/index.js';
import { startControlServer } from '../control/index.js';
import { HandleTable } from '../daemon/handles.js';
import type { MethodContext } from '../daemon/index.js';
import { runMcpStdio } from '../mcp/server.js';
import { FileSystemPolicyResolver } from '../policy/index.js';
import { DEFAULT_RPC_PORT, startRpcServer, type RpcProxyServer } from '../rpc/index.js';

/**
 * sigil-mcp: single-process MCP server for sigil. Spawned by Claude Code per
 * session via the .claude/settings.json mcpServers entry.
 *
 * Lifecycle:
 *   - On startup: ensures ~/.sigil/{,keys/,control/} exist (0o700), opens the
 *     audit log, constructs an EMPTY (locked) HandleTable, binds a per-session
 *     control socket at ~/.sigil/control/<pid>.sock (0o600).
 *   - During the session: runs the MCP wire loop on stdio. Sign methods
 *     return DAEMON_LOCKED until the user runs `sigil unlock`, which pushes
 *     the passphrase over the control socket; the HandleTable loads the
 *     encrypted keyfiles from disk and the session is unlocked.
 *   - On stdin close (Claude exited): closes the control socket, locks +
 *     disposes the HandleTable, closes the audit writer, exits.
 *
 * Each session owns a distinct socket (named for its PID), so multiple Claude
 * windows no longer contend for a single control.sock — `sigil unlock` fans
 * out across every socket in the directory and unlocks them all at once.
 *
 * The control socket is unref'd so it doesn't keep the loop alive on its own;
 * stdin alone gates process lifetime.
 */
async function main(): Promise<void> {
  const paths = resolvePaths(process.env);
  mkdirSync(paths.home, { recursive: true, mode: 0o700 });
  mkdirSync(paths.keysDir, { recursive: true, mode: 0o700 });
  mkdirSync(paths.policyDir, { recursive: true, mode: 0o700 });
  mkdirSync(paths.controlDir, { recursive: true, mode: 0o700 });
  // mkdir's `mode` only applies to a freshly-created dir (and is masked by
  // umask), so re-assert 0o700 in case the dir pre-existed with looser perms.
  // The per-socket file gets its own 0o600 from the control server on bind.
  try {
    chmodSync(paths.controlDir, 0o700);
  } catch {
    /* best-effort */
  }
  const socketPath = sessionSocketPath(paths.controlDir, process.pid);

  // Load config + fail-closed check. If any portal policy requires OOB
  // confirmation but no transport is configured, refuse to start — running
  // would silently degrade every confirm-gated sign to a deny.
  const config = loadConfig(paths.configFile);
  enforceConfirmTransportPresence(config, paths.policyDir);

  // Stand up the confirm pipeline only if a transport is configured. When
  // it's absent, sign_transaction will reject any tx that hits a confirm
  // threshold via the gatePolicy fail-closed path inside daemon/methods.ts.
  let confirmGate: ConfirmGate | undefined;
  let ackServer: AckServer | undefined;
  if (config.confirm?.ntfy) {
    const transport: ConfirmTransport = new NtfyTransport(config.confirm.ntfy);
    ackServer = await startAckServer();
    const opts: ConstructorParameters<typeof ConfirmGate>[0] = {
      transport,
      ackServer,
      ...(config.confirm.timeoutMs !== undefined ? { timeoutMs: config.confirm.timeoutMs } : {}),
    };
    confirmGate = new ConfirmGate(opts);
    process.stderr.write(
      `sigil-mcp: confirm transport "${transport.name}" ready (ack on ${ackServer.baseUrl})\n`,
    );
  }

  const handles = new HandleTable();
  const audit = new AuditWriter(paths.auditLog);
  const policy = new FileSystemPolicyResolver(paths.policyDir);

  const context: MethodContext = {
    handles,
    audit,
    policy,
    ...(confirmGate ? { confirm: confirmGate } : {}),
  };

  // Local JSON-RPC signing proxy (forge/hardhat/cast integration). Shares
  // `context` with the MCP loop, so its signs run the identical policy →
  // confirm → audit pipeline. Multiple Claude windows each spawn a
  // sigil-mcp; only the first binds the port — the others log and carry on,
  // since any one session's proxy serves the machine.
  let rpcServer: RpcProxyServer | undefined;
  let rpcProxyPort: number | undefined;
  if (config.rpc) {
    try {
      rpcServer = await startRpcServer({
        config: config.rpc,
        ctx: context,
        onLog: (e) => process.stderr.write(`rpc: ${JSON.stringify(e)}\n`),
      });
      rpcProxyPort = rpcServer.port;
      const upstreamOrigin = new URL(config.rpc.upstream).origin;
      process.stderr.write(
        `sigil-mcp: json-rpc signing proxy on ${rpcServer.url} ` +
          `(portal "${config.rpc.portal}", upstream ${upstreamOrigin})\n`,
      );
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'EADDRINUSE') {
        // Another session already serves the proxy on the configured port —
        // still advertise it to the model below; it's the same config.
        rpcProxyPort = config.rpc.port ?? DEFAULT_RPC_PORT;
        process.stderr.write(
          `sigil-mcp: rpc port busy — another sigil-mcp session already serves the proxy\n`,
        );
      } else {
        throw err;
      }
    }
  }

  // Tell the model the proxy exists — tool descriptions are its only
  // discovery channel. The authenticated URL is included on purpose: the
  // token gates other local software, not the agent (which is the intended
  // client and cannot read the config file past the ward hooks).
  let toolNotes: Record<string, string> | undefined;
  if (config.rpc && rpcProxyPort !== undefined) {
    const authedUrl = `http://sigil:${config.rpc.token}@127.0.0.1:${rpcProxyPort}`;
    toolNotes = {
      sigil_eth_sign_transaction:
        `NOTE: sigil also serves a local JSON-RPC signing proxy for portal ` +
        `"${config.rpc.portal}" at ${authedUrl} (chain per its configured upstream). ` +
        `For Foundry/Hardhat/web3-tool workflows — especially contract deployments — ` +
        `prefer that endpoint over transcribing calldata into this tool: e.g. ` +
        `forge script <Script> --rpc-url '${authedUrl}' --unlocked --sender <portal address> --broadcast. ` +
        `Its eth_sendTransaction fills nonce/gas/fees automatically, broadcasts via the ` +
        `upstream, and runs the same policy, confirm, and audit pipeline as this tool.`,
    };
  }

  let controlClosed = false;
  let control: Awaited<ReturnType<typeof startControlServer>> | null = null;
  try {
    control = await startControlServer({
      socketPath,
      keysDir: paths.keysDir,
      policyDir: paths.policyDir,
      handles,
      onLog: (e) => process.stderr.write(`control: ${JSON.stringify(e)}\n`),
    });
  } catch (err) {
    // The per-PID socket is ours alone, so this is genuinely exceptional
    // (e.g. controlDir not writable). Stay up so the MCP stdio still works,
    // but warn — without a control socket this session can't be unlocked and
    // sign calls will return DAEMON_LOCKED.
    process.stderr.write(
      `sigil-mcp: control socket unavailable at ${socketPath} (${(err as Error).message}). ` +
        `This session will stay locked; sign calls will return DAEMON_LOCKED.\n`,
    );
  }

  if (control) {
    process.stderr.write(
      `sigil-mcp: ready (locked; run "sigil unlock" to load keys from ${paths.keysDir})\n`,
    );
  } else {
    process.stderr.write(`sigil-mcp: ready (locked — no control socket; cannot be unlocked)\n`);
  }

  const shutdown = (): void => {
    handles.dispose();
    audit.close();
    if (!controlClosed && control) {
      controlClosed = true;
      control.close().catch(() => {
        /* best-effort */
      });
    }
    if (ackServer) {
      ackServer.close().catch(() => {
        /* best-effort */
      });
    }
    if (rpcServer) {
      rpcServer.close().catch(() => {
        /* best-effort */
      });
    }
  };
  process.on('exit', shutdown);
  process.on('SIGINT', () => process.exit(0));
  process.on('SIGTERM', () => process.exit(0));

  await runMcpStdio({
    context,
    ...(toolNotes ? { toolNotes } : {}),
    stdin: process.stdin,
    stdout: process.stdout,
    onLog: (e) => process.stderr.write(JSON.stringify(e) + '\n'),
  });

  // stdin closed (Claude exited) — close the control socket explicitly so
  // we don't leave a stale socket file behind.
  if (control && !controlClosed) {
    controlClosed = true;
    await control.close();
  }
  if (ackServer) await ackServer.close();
  if (rpcServer) await rpcServer.close();
  process.exit(0);
}

main().catch((err: Error) => {
  process.stderr.write(`sigil-mcp: ${err.message}\n`);
  process.exit(1);
});
