import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { equal, ok } from 'node:assert/strict';
import { isValidMnemonic, redactMnemonics } from '../../src/hooks/bip39.js';
import { BIP39_WORDLIST } from '../../src/hooks/bip39-wordlist.js';

// Official BIP-39 English test vectors (trezor/python-mnemonic). If the
// vendored wordlist is wrong by even one word, these fail — so they, not the
// vendoring step, are what establishes the wordlist's correctness.
const OFFICIAL_VALID = [
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  'legal winner thank year wave sausage worth useful legal winner thank yellow',
  'letter advice cage absurd amount doctor acoustic avoid letter advice cage above',
  'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong',
  // 24-word (256-bit entropy) vector
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art',
];

test('vendored wordlist is the canonical 2048-word BIP-39 English list', () => {
  equal(BIP39_WORDLIST.length, 2048);
  const sha = createHash('sha256')
    .update(BIP39_WORDLIST.join('\n') + '\n')
    .digest('hex');
  equal(sha, '2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda');
});

test('isValidMnemonic accepts every official BIP-39 vector', () => {
  for (const m of OFFICIAL_VALID) {
    ok(isValidMnemonic(m.split(' ')), m);
  }
});

test('isValidMnemonic rejects a phrase with a bad checksum', () => {
  // 12× "abandon" is all-in-wordlist but the checksum does not match.
  equal(isValidMnemonic(Array(12).fill('abandon')), false);
});

test('isValidMnemonic rejects a single-word mutation of a valid phrase', () => {
  // Swap the last word of a valid 12-word phrase → checksum breaks.
  const words = OFFICIAL_VALID[1]!.split(' ');
  words[words.length - 1] = 'zoo';
  equal(isValidMnemonic(words), false);
});

test('isValidMnemonic rejects non-standard lengths', () => {
  equal(isValidMnemonic('abandon about'.split(' ')), false); // 2 words
  equal(isValidMnemonic(Array(13).fill('abandon')), false); // 13 words
});

test('isValidMnemonic rejects a word outside the list', () => {
  const words = OFFICIAL_VALID[0]!.split(' ');
  words[0] = 'notaword';
  equal(isValidMnemonic(words), false);
});

test('redactMnemonics replaces a valid phrase and counts it', () => {
  const { text, count } = redactMnemonics(`seed: ${OFFICIAL_VALID[0]} done`, '<X>');
  equal(count, 1);
  ok(text.includes('<X>'));
  ok(!text.includes('abandon'));
  ok(text.startsWith('seed: '));
  ok(text.endsWith(' done'));
});

test('redactMnemonics leaves ordinary prose alone', () => {
  // Common short lowercase words, but not a checksum-valid phrase.
  const prose = 'the quick brown fox jumps over the lazy dog and then runs off';
  equal(redactMnemonics(prose, '<X>').count, 0);
});

test('redactMnemonics leaves wordlist-heavy prose alone (no valid run)', () => {
  // Several wordlist words, but interrupted by non-list words → no valid window.
  const s = 'please review the above advice and abandon the absurd amount about now';
  equal(redactMnemonics(s, '<X>').count, 0);
});

test('redactMnemonics prefers the longest window (24-word phrase → one redaction)', () => {
  const { count } = redactMnemonics(OFFICIAL_VALID[4]!, '<X>');
  equal(count, 1);
});
