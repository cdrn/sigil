import { keccak256 } from './keccak.js';
import { signDigest } from './secp.js';
import { serializeEthSignature } from './sign-message.js';

export interface TypedDataDomain {
  name?: string;
  version?: string;
  chainId?: number | bigint;
  verifyingContract?: `0x${string}`;
  salt?: `0x${string}`;
}

export interface TypedDataField {
  name: string;
  type: string;
}

export interface TypedDataTypes {
  EIP712Domain?: TypedDataField[];
  [typeName: string]: TypedDataField[] | undefined;
}

export interface TypedData {
  types: TypedDataTypes;
  primaryType: string;
  domain: TypedDataDomain;
  message: Record<string, unknown>;
}

function hexToBuf(h: string): Buffer {
  const s = h.startsWith('0x') ? h.slice(2) : h;
  return Buffer.from(s, 'hex');
}

function bigToBuf(n: number | bigint, bytes: number): Buffer {
  let v = typeof n === 'bigint' ? n : BigInt(n);
  if (v < 0n) {
    // two's complement for signed int<N>
    v = (1n << BigInt(bytes * 8)) + v;
  }
  let hex = v.toString(16);
  if (hex.length > bytes * 2) throw new Error(`integer overflow for ${bytes}-byte slot`);
  hex = hex.padStart(bytes * 2, '0');
  return Buffer.from(hex, 'hex');
}

/**
 * Collect all dependencies of a struct type, transitively, sorted alphabetically
 * with the primary type first.
 */
function findDependencies(primaryType: string, types: TypedDataTypes, deps: Set<string> = new Set()): Set<string> {
  if (deps.has(primaryType)) return deps;
  const fields = types[primaryType];
  if (!fields) return deps;
  deps.add(primaryType);
  for (const field of fields) {
    const baseType = field.type.replace(/(\[\d*\])+$/, '');
    if (types[baseType] && !deps.has(baseType)) {
      findDependencies(baseType, types, deps);
    }
  }
  return deps;
}

/**
 * encodeType: "Type(field1 t1,field2 t2)Dep1(...)Dep2(...)"
 */
export function encodeType(primaryType: string, types: TypedDataTypes): string {
  const deps = findDependencies(primaryType, types);
  deps.delete(primaryType);
  const ordered = [primaryType, ...Array.from(deps).sort()];
  return ordered
    .map((t) => {
      const fields = types[t];
      if (!fields) throw new Error(`type ${t} not defined`);
      return `${t}(${fields.map((f) => `${f.type} ${f.name}`).join(',')})`;
    })
    .join('');
}

export function typeHash(primaryType: string, types: TypedDataTypes): Buffer {
  return keccak256(Buffer.from(encodeType(primaryType, types), 'utf8'));
}

function encodeValue(type: string, value: unknown, types: TypedDataTypes): Buffer {
  // Arrays
  const arrayMatch = type.match(/^(.*)(\[(\d*)\])$/);
  if (arrayMatch) {
    const inner = arrayMatch[1]!;
    if (!Array.isArray(value)) throw new Error(`expected array for ${type}`);
    const encoded = Buffer.concat(value.map((v) => encodeValue(inner, v, types)));
    return keccak256(encoded);
  }
  // Structs
  if (types[type]) {
    return hashStruct(type, value as Record<string, unknown>, types);
  }
  // Atomic types
  if (type === 'string') {
    return keccak256(Buffer.from(value as string, 'utf8'));
  }
  if (type === 'bytes') {
    const buf = typeof value === 'string' ? hexToBuf(value) : (value as Buffer);
    return keccak256(buf);
  }
  if (type === 'address') {
    const buf = hexToBuf(value as string);
    if (buf.length !== 20) throw new Error(`address must be 20 bytes, got ${buf.length}`);
    return Buffer.concat([Buffer.alloc(12), buf]);
  }
  if (type === 'bool') {
    return bigToBuf(value ? 1 : 0, 32);
  }
  const uintMatch = type.match(/^u?int(\d+)?$/);
  if (uintMatch) {
    // Both int and uint are encoded as 32-byte big-endian.
    return bigToBuf(value as number | bigint, 32);
  }
  const bytesMatch = type.match(/^bytes(\d+)$/);
  if (bytesMatch) {
    const len = parseInt(bytesMatch[1]!, 10);
    const buf = typeof value === 'string' ? hexToBuf(value) : (value as Buffer);
    if (buf.length !== len) throw new Error(`expected bytes${len}, got ${buf.length} bytes`);
    // Right-padded to 32 bytes
    const out = Buffer.alloc(32);
    buf.copy(out, 0);
    return out;
  }
  throw new Error(`unsupported type ${type}`);
}

export function hashStruct(primaryType: string, data: Record<string, unknown>, types: TypedDataTypes): Buffer {
  const fields = types[primaryType];
  if (!fields) throw new Error(`type ${primaryType} not defined`);
  const encoded = [typeHash(primaryType, types)];
  for (const field of fields) {
    encoded.push(encodeValue(field.type, data[field.name], types));
  }
  return keccak256(Buffer.concat(encoded));
}

/**
 * The EIP-712 digest: keccak256("\x19\x01" || domainSeparator || hashStruct(primaryType, message)).
 */
export function typedDataDigest(td: TypedData): Buffer {
  // Build EIP712Domain type from the domain fields actually present (canonical order).
  const domainFields: TypedDataField[] = [];
  if (td.domain.name !== undefined) domainFields.push({ name: 'name', type: 'string' });
  if (td.domain.version !== undefined) domainFields.push({ name: 'version', type: 'string' });
  if (td.domain.chainId !== undefined) domainFields.push({ name: 'chainId', type: 'uint256' });
  if (td.domain.verifyingContract !== undefined) domainFields.push({ name: 'verifyingContract', type: 'address' });
  if (td.domain.salt !== undefined) domainFields.push({ name: 'salt', type: 'bytes32' });

  const typesWithDomain: TypedDataTypes = { ...td.types, EIP712Domain: domainFields };
  const domainHash = hashStruct('EIP712Domain', td.domain as unknown as Record<string, unknown>, typesWithDomain);
  const messageHash = hashStruct(td.primaryType, td.message, td.types);
  return keccak256(Buffer.concat([Buffer.from([0x19, 0x01]), domainHash, messageHash]));
}

export function signTypedData(td: TypedData, privateKey: Buffer | Uint8Array): Buffer {
  const digest = typedDataDigest(td);
  return serializeEthSignature(signDigest(digest, privateKey));
}
