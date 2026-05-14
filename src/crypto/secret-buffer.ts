import { inspect } from 'node:util';

export class SecretBufferDisposedError extends Error {
  constructor() {
    super('SecretBuffer has been disposed');
    this.name = 'SecretBufferDisposedError';
  }
}

export class SecretBufferSerializeError extends Error {
  constructor() {
    super('SecretBuffer cannot be serialized; use .bytes() if you really need the value');
    this.name = 'SecretBufferSerializeError';
  }
}

export class SecretBuffer {
  #buf: Buffer | null;

  constructor(source: Buffer | Uint8Array) {
    this.#buf = Buffer.from(source);
  }

  bytes(): Buffer {
    if (this.#buf === null) throw new SecretBufferDisposedError();
    return this.#buf;
  }

  get length(): number {
    if (this.#buf === null) throw new SecretBufferDisposedError();
    return this.#buf.length;
  }

  dispose(): void {
    if (this.#buf !== null) {
      this.#buf.fill(0);
      this.#buf = null;
    }
  }

  get isDisposed(): boolean {
    return this.#buf === null;
  }

  toString(): never {
    throw new SecretBufferSerializeError();
  }

  toJSON(): never {
    throw new SecretBufferSerializeError();
  }

  [inspect.custom](): string {
    return this.#buf === null ? '<SecretBuffer disposed>' : '<SecretBuffer redacted>';
  }
}
