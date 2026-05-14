import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

export const AEAD_KEY_LEN = 32;
export const AEAD_NONCE_LEN = 24;
export const AEAD_TAG_LEN = 16;

export class AeadVerifyError extends Error {
  constructor(cause?: unknown) {
    super('AEAD verification failed (wrong key, wrong nonce, tampered ciphertext, or mismatched AAD)');
    this.name = 'AeadVerifyError';
    if (cause !== undefined) this.cause = cause;
  }
}

export function aeadEncrypt(
  key: Buffer | Uint8Array,
  nonce: Buffer | Uint8Array,
  plaintext: Buffer | Uint8Array,
  aad?: Buffer | Uint8Array,
): Buffer {
  if (key.length !== AEAD_KEY_LEN) {
    throw new Error(`key must be ${AEAD_KEY_LEN} bytes, got ${key.length}`);
  }
  if (nonce.length !== AEAD_NONCE_LEN) {
    throw new Error(`nonce must be ${AEAD_NONCE_LEN} bytes, got ${nonce.length}`);
  }
  const cipher = xchacha20poly1305(key, nonce, aad);
  return Buffer.from(cipher.encrypt(plaintext));
}

export function aeadDecrypt(
  key: Buffer | Uint8Array,
  nonce: Buffer | Uint8Array,
  ciphertext: Buffer | Uint8Array,
  aad?: Buffer | Uint8Array,
): Buffer {
  if (key.length !== AEAD_KEY_LEN) {
    throw new Error(`key must be ${AEAD_KEY_LEN} bytes, got ${key.length}`);
  }
  if (nonce.length !== AEAD_NONCE_LEN) {
    throw new Error(`nonce must be ${AEAD_NONCE_LEN} bytes, got ${nonce.length}`);
  }
  const cipher = xchacha20poly1305(key, nonce, aad);
  try {
    return Buffer.from(cipher.decrypt(ciphertext));
  } catch (err) {
    throw new AeadVerifyError(err);
  }
}
