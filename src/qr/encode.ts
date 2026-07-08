/**
 * QR Code encoder — thin adapter over `qrcode-generator` (Kazuhiko Arase's
 * reference implementation, pinned at exact version, zero transitive deps).
 *
 * Defaults to byte mode so the input string is preserved verbatim,
 * including case. The earlier alphanumeric-mode-only API uppercased
 * everything, which broke wallets that validate ETH addresses against
 * EIP-55 (lowercase `0x` prefix; mixed-case checksum).
 *
 * For pure-uppercase / pure-numeric payloads, alphanumeric mode is
 * denser; opt in via the `mode` option.
 */

import qrcode = require('qrcode-generator');

const ALPHANUMERIC_RE = /^[0-9A-Z $%*+\-./:]*$/;

export type QrMode = 'Byte' | 'Alphanumeric';

export type QrEcLevel = 'L' | 'M' | 'Q' | 'H';

export interface QrEncodeOpts {
  /**
   * Force a specific version (1–40). If omitted, the library picks the
   * smallest fitting version for the input.
   */
  version?: number;
  /**
   * QR encoding mode. Defaults to `'Byte'` (case-preserving, works for
   * any UTF-8 string). `'Alphanumeric'` is denser but only supports
   * digits, uppercase A–Z, space, and `$%*+-./:`.
   */
  mode?: QrMode;
  /**
   * Error-correction level. Defaults to `'M'` (~15% damage tolerance):
   * our QRs are phone-scanned off terminal glass — glare, moiré, themed
   * low-contrast rendering — where L (~7%) is marginal. For the payload
   * we care most about (a 42-char 0x address), M costs nothing: it fits
   * QR version 3 (29×29) at either level.
   */
  ecLevel?: QrEcLevel;
}

/**
 * Encode a string into a QR bit matrix.
 *
 * In byte mode (the default) any input is accepted as-is. In alphanumeric
 * mode we validate up front rather than letting the library silently
 * fall back to byte mode, so callers who asked for the denser encoding
 * get a clear error if their input doesn't qualify.
 */
export function encode(input: string, opts: QrEncodeOpts = {}): boolean[][] {
  const mode: QrMode = opts.mode ?? 'Byte';
  if (mode === 'Alphanumeric' && !ALPHANUMERIC_RE.test(input)) {
    throw new Error(
      `qr: input contains chars outside the alphanumeric set: ${JSON.stringify(input)}`,
    );
  }
  const typeNumber = (opts.version ?? 0) as Parameters<typeof qrcode>[0];
  const qr = qrcode(typeNumber, opts.ecLevel ?? 'M');
  qr.addData(input, mode);
  qr.make();
  const size = qr.getModuleCount();
  const matrix: boolean[][] = [];
  for (let r = 0; r < size; r++) {
    const row: boolean[] = [];
    for (let c = 0; c < size; c++) row.push(qr.isDark(r, c));
    matrix.push(row);
  }
  return matrix;
}
