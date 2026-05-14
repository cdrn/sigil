import { randomBytes } from 'node:crypto';
import { AEAD_NONCE_LEN, aeadDecrypt, aeadEncrypt, AeadVerifyError } from './aead.js';
import { DEFAULT_KDF_PARAMS, deriveKey, SALT_LEN, type KdfParams } from './kdf.js';
import { SecretBuffer } from './secret-buffer.js';

const MAGIC = Buffer.from('SIGIL', 'ascii');
const FORMAT_VERSION = 0x01;
const KDF_ARGON2ID = 0x01;
const AEAD_XCHACHA20POLY1305 = 0x01;

export const HEADER_LEN =
  MAGIC.length + // 5
  1 + // format version
  1 + // kdf type
  4 + // kdf.m (uint32 BE, KiB)
  1 + // kdf.t
  1 + // kdf.p
  1 + // aead type
  2 + // reserved
  SALT_LEN + // 16
  AEAD_NONCE_LEN; // 24
// total: 56

export class KeyfileFormatError extends Error {
  constructor(reason: string) {
    super(`keyfile format error: ${reason}`);
    this.name = 'KeyfileFormatError';
  }
}

export class WrongPassphraseError extends Error {
  constructor() {
    super('wrong passphrase or tampered keyfile');
    this.name = 'WrongPassphraseError';
  }
}

interface ParsedHeader {
  kdf: KdfParams;
  salt: Buffer;
  nonce: Buffer;
}

function buildHeader(salt: Buffer, nonce: Buffer, params: KdfParams): Buffer {
  const h = Buffer.alloc(HEADER_LEN);
  let off = 0;
  MAGIC.copy(h, off);
  off += MAGIC.length;
  h.writeUInt8(FORMAT_VERSION, off++);
  h.writeUInt8(KDF_ARGON2ID, off++);
  h.writeUInt32BE(params.m, off);
  off += 4;
  h.writeUInt8(params.t, off++);
  h.writeUInt8(params.p, off++);
  h.writeUInt8(AEAD_XCHACHA20POLY1305, off++);
  h.writeUInt16BE(0, off);
  off += 2;
  salt.copy(h, off);
  off += SALT_LEN;
  nonce.copy(h, off);
  off += AEAD_NONCE_LEN;
  return h;
}

function parseHeader(buf: Buffer): ParsedHeader {
  if (buf.length < HEADER_LEN) {
    throw new KeyfileFormatError(`truncated: need at least ${HEADER_LEN} bytes, got ${buf.length}`);
  }
  let off = 0;
  if (!buf.subarray(off, off + MAGIC.length).equals(MAGIC)) {
    throw new KeyfileFormatError('bad magic');
  }
  off += MAGIC.length;
  const ver = buf.readUInt8(off++);
  if (ver !== FORMAT_VERSION) {
    throw new KeyfileFormatError(`unsupported format version ${ver}`);
  }
  const kdfType = buf.readUInt8(off++);
  if (kdfType !== KDF_ARGON2ID) {
    throw new KeyfileFormatError(`unsupported kdf type ${kdfType}`);
  }
  const m = buf.readUInt32BE(off);
  off += 4;
  const t = buf.readUInt8(off++);
  const p = buf.readUInt8(off++);
  const aeadType = buf.readUInt8(off++);
  if (aeadType !== AEAD_XCHACHA20POLY1305) {
    throw new KeyfileFormatError(`unsupported aead type ${aeadType}`);
  }
  off += 2; // reserved
  const salt = Buffer.from(buf.subarray(off, off + SALT_LEN));
  off += SALT_LEN;
  const nonce = Buffer.from(buf.subarray(off, off + AEAD_NONCE_LEN));
  return { kdf: { m, t, p }, salt, nonce };
}

export function sealKey(
  plainKey: Buffer | Uint8Array,
  passphrase: Buffer | Uint8Array,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Buffer {
  const salt = randomBytes(SALT_LEN);
  const nonce = randomBytes(AEAD_NONCE_LEN);
  const header = buildHeader(salt, nonce, params);
  const derivedKey = deriveKey(passphrase, salt, params);
  try {
    const ciphertext = aeadEncrypt(derivedKey, nonce, plainKey, header);
    return Buffer.concat([header, ciphertext]);
  } finally {
    derivedKey.fill(0);
  }
}

export function unsealKey(
  keyfileBytes: Buffer,
  passphrase: Buffer | Uint8Array,
): SecretBuffer {
  const { kdf, salt, nonce } = parseHeader(keyfileBytes);
  const header = keyfileBytes.subarray(0, HEADER_LEN);
  const ciphertext = keyfileBytes.subarray(HEADER_LEN);
  const derivedKey = deriveKey(passphrase, salt, kdf);
  try {
    const plain = aeadDecrypt(derivedKey, nonce, ciphertext, header);
    return new SecretBuffer(plain);
  } catch (err) {
    if (err instanceof AeadVerifyError) throw new WrongPassphraseError();
    throw err;
  } finally {
    derivedKey.fill(0);
  }
}
