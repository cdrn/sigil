import { sha256 } from '@noble/hashes/sha2.js';
import { BIP39_WORDLIST } from './bip39-wordlist.js';

/**
 * BIP-39 mnemonic detection for the output redactor.
 *
 * A seed phrase is the most catastrophic thing that can leak from a signing
 * tool — it's the key itself, in the most portable form. But "N lowercase
 * words" is a terrible detector: ordinary prose trips it constantly. So we
 * validate the BIP-39 checksum. A run of words only redacts if it is an
 * *actually valid* mnemonic (every word in the list AND the trailing
 * checksum bits match sha256 of the entropy), which drives false positives
 * to essentially zero — a random 12-word English sentence has a 1-in-16
 * chance of an accidental 4-bit checksum match, and every word also has to
 * be one of the 2048.
 */

const WORD_INDEX: ReadonlyMap<string, number> = new Map(BIP39_WORDLIST.map((w, i) => [w, i]));

/** Valid BIP-39 mnemonic word counts (ENT 128..256 bits, +CS). */
const VALID_LENGTHS = [12, 15, 18, 21, 24] as const;
const MAX_LENGTH = 24;

/**
 * True iff `words` is a checksum-valid BIP-39 mnemonic. Length must be one of
 * the standard values and every word must be in the wordlist.
 */
export function isValidMnemonic(words: readonly string[]): boolean {
  if (!VALID_LENGTHS.includes(words.length as (typeof VALID_LENGTHS)[number])) return false;

  // Pack 11 bits per word into a bit array.
  const totalBits = words.length * 11;
  const checksumBits = totalBits / 33; // = ENT/32
  const entropyBits = totalBits - checksumBits;
  const bits: number[] = [];
  for (const w of words) {
    const idx = WORD_INDEX.get(w);
    if (idx === undefined) return false;
    for (let b = 10; b >= 0; b--) bits.push((idx >> b) & 1);
  }

  // First entropyBits bits are the entropy; pack them into bytes.
  const entropyBytes = new Uint8Array(entropyBits / 8);
  for (let i = 0; i < entropyBits; i++) {
    if (bits[i] === 1) entropyBytes[i >> 3]! |= 1 << (7 - (i % 8));
  }

  // The checksum is the first `checksumBits` bits of sha256(entropy).
  const hash = sha256(entropyBytes);
  for (let i = 0; i < checksumBits; i++) {
    const expected = (hash[i >> 3]! >> (7 - (i % 8))) & 1;
    if (bits[entropyBits + i] !== expected) return false;
  }
  return true;
}

/**
 * Scan text for checksum-valid BIP-39 mnemonics and replace each with
 * `placeholder`. Returns the rewritten text and the number of phrases
 * redacted.
 *
 * Approach: tokenize into maximal runs of wordlist words separated by single
 * spaces, then within each run greedily match the longest valid mnemonic
 * window (24→12) so a 24-word phrase isn't mistaken for two 12-word ones.
 */
export function redactMnemonics(
  text: string,
  placeholder: string,
): { text: string; count: number } {
  // Match runs of lowercase words separated by single ASCII spaces. BIP-39
  // phrases are lowercase and single-space-joined; staying strict keeps us
  // off normal prose that has punctuation, capitals, or double spaces.
  const runRe = /[a-z]+(?: [a-z]+)+/g;
  let count = 0;
  const out = text.replace(runRe, (run) => {
    const tokens = run.split(' ');
    // Only bother if there's at least one all-in-wordlist window of min length.
    let result = '';
    let i = 0;
    while (i < tokens.length) {
      let matchedLen = 0;
      for (const len of [...VALID_LENGTHS].reverse()) {
        if (len > MAX_LENGTH) continue;
        if (i + len > tokens.length) continue;
        const window = tokens.slice(i, i + len);
        if (isValidMnemonic(window)) {
          matchedLen = len;
          break;
        }
      }
      if (matchedLen > 0) {
        count++;
        result += (result === '' ? '' : ' ') + placeholder;
        i += matchedLen;
      } else {
        result += (result === '' ? '' : ' ') + tokens[i];
        i++;
      }
    }
    return result;
  });
  return { text: out, count };
}
