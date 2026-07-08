import type { ReadStream } from 'node:tty';

/**
 * Read a passphrase from a TTY without echoing it. Returns the passphrase as a
 * Buffer so the caller can zeroize it after use.
 *
 * The implementation reads byte-by-byte in raw mode, handling Enter, backspace,
 * and Ctrl-C. It is intentionally testable: pass a stdin/stderr override.
 */
export interface ReadPassphraseDeps {
  stdin?: ReadStream;
  stderr?: NodeJS.WritableStream;
}

export function readPassphrase(prompt: string, deps: ReadPassphraseDeps = {}): Promise<Buffer> {
  const stdin = deps.stdin ?? (process.stdin as ReadStream);
  const stderr = deps.stderr ?? process.stderr;

  if (!stdin.isTTY) {
    return Promise.reject(
      new Error(
        'readPassphrase: stdin is not a TTY; pipe in via process substitution or use --passphrase-fd',
      ),
    );
  }

  stderr.write(prompt);

  const wasRaw = stdin.isRaw;
  stdin.setRawMode(true);
  stdin.resume();

  return new Promise((resolve, reject) => {
    let buf = '';
    const onData = (chunk: Buffer): void => {
      const s = chunk.toString('utf8');
      for (const c of s) {
        const code = c.charCodeAt(0);
        if (code === 0x03) {
          // Ctrl-C
          cleanup();
          stderr.write('\n');
          reject(new Error('passphrase entry aborted'));
          return;
        }
        if (code === 0x0d || code === 0x0a) {
          // Enter
          cleanup();
          stderr.write('\n');
          resolve(Buffer.from(buf, 'utf8'));
          return;
        }
        if (code === 0x7f || code === 0x08) {
          // Backspace
          buf = buf.slice(0, -1);
          continue;
        }
        if (code < 0x20) continue;
        buf += c;
      }
    };
    const cleanup = (): void => {
      stdin.removeListener('data', onData);
      stdin.pause();
      stdin.setRawMode(wasRaw);
    };
    stdin.on('data', onData);
  });
}
