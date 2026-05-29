/**
 * Render a QR bit matrix as terminal text.
 *
 * We use the upper-half-block character `▀` (U+2580) so two QR rows pack
 * into one terminal row, preserving the QR's natural square aspect ratio
 * on terminals where character cells are ~2:1 tall. Foreground = top
 * pixel, background = bottom pixel. Dark modules render as foreground
 * black; light modules as the terminal's background.
 *
 * A 4-module quiet zone (ISO/IEC 18004 §6.3) is added around the matrix
 * so scanners reliably locate the finder patterns.
 */

export interface RenderOpts {
  /** Modules of light padding around the matrix (default 4 — the QR spec minimum). */
  quietZone?: number;
}

export function renderTerminal(matrix: boolean[][], opts: RenderOpts = {}): string {
  const quiet = opts.quietZone ?? 4;
  const size = matrix.length;
  // Build a padded matrix so the renderer doesn't need to special-case the border.
  const padded: boolean[][] = [];
  const pad = (): boolean[] => Array(size + quiet * 2).fill(false);
  for (let i = 0; i < quiet; i++) padded.push(pad());
  for (let r = 0; r < size; r++) {
    const row = pad();
    for (let c = 0; c < size; c++) row[c + quiet] = matrix[r]![c]!;
    padded.push(row);
  }
  for (let i = 0; i < quiet; i++) padded.push(pad());

  const lines: string[] = [];
  // ANSI: black FG on white BG so dark modules show as black on light
  // terminals AND light terminals. (No-color terminals fall back to the
  // raw block character which is still scannable on most setups.)
  const ON = '\x1b[40m'; // background black
  const OFF = '\x1b[47m'; // background white
  const RESET = '\x1b[0m';

  for (let r = 0; r < padded.length; r += 2) {
    let line = '';
    let mode: 'on' | 'off' | null = null;
    for (let c = 0; c < padded[0]!.length; c++) {
      const top = padded[r]![c]!;
      const bot = (padded[r + 1] ?? pad())[c]!;
      // Pick the colour pair that draws this column: we use the cell-bg
      // ANSI colour to draw the BOTTOM half, then the printed character
      // ('▀' / ' ' / '█') decides what the TOP half looks like.
      const need: 'on' | 'off' = bot ? 'on' : 'off';
      if (need !== mode) {
        line += need === 'on' ? ON : OFF;
        mode = need;
      }
      // Top half — print a foreground-coloured upper half-block if top is
      // dark, else a space (which leaves the background colour showing).
      line += top ? '\x1b[30m▀' : ' ';
    }
    line += RESET;
    lines.push(line);
  }
  return lines.join('\n') + '\n';
}

/**
 * Plain ASCII renderer for tests / non-ANSI consumers. Two characters per
 * QR module so the output is roughly square in any monospaced font.
 */
export function renderAscii(matrix: boolean[][], opts: RenderOpts = {}): string {
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
