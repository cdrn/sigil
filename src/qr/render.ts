/**
 * Render a QR bit matrix as terminal text.
 *
 * Each QR module becomes `██` (two full-block chars wide × one line tall).
 * Monospace terminal cells are ~1:2 (width:height), so 2 chars wide × 1
 * line tall lands at roughly square — the shape a phone camera expects.
 *
 * We deliberately avoid the half-block trick (`▀ ▄ █`) because it requires
 * the terminal to render line spacing such that `▀` aligns flush with the
 * `▄` below — Warp, iTerm with custom fonts, and tmux all add sub-pixel
 * gaps that produce non-square modules and break scanner lock.
 *
 * We also deliberately avoid ANSI background colours: themed terminals
 * (Warp's default theme, low-contrast iTerm themes) render `[40m` /
 * `[47m` at insufficient contrast for a phone camera. Plain block chars
 * inherit the terminal's natural fg/bg contrast.
 *
 * On a dark-theme terminal this renders as light-on-dark (inverted
 * polarity); on a light theme, dark-on-light. Phone scanners accept
 * either polarity. A 4-module quiet zone (ISO/IEC 18004 §6.3) is added
 * so scanners reliably locate the finder patterns.
 */

export interface RenderOpts {
  /** Modules of light padding around the matrix (default 4 — the QR spec minimum). */
  quietZone?: number;
}

export function renderTerminal(matrix: boolean[][], opts: RenderOpts = {}): string {
  const quiet = opts.quietZone ?? 4;
  const size = matrix.length;
  const out: string[] = [];
  for (let r = -quiet; r < size + quiet; r++) {
    let line = '';
    for (let c = -quiet; c < size + quiet; c++) {
      const dark = r >= 0 && r < size && c >= 0 && c < size && matrix[r]![c]!;
      line += dark ? '██' : '  ';
    }
    out.push(line);
  }
  return out.join('\n') + '\n';
}

/**
 * Alias for {@link renderTerminal}. Kept for callers that imported the
 * old name; renderTerminal is now also pure ASCII / Unicode block chars
 * with no ANSI dependency.
 */
export const renderAscii = renderTerminal;
