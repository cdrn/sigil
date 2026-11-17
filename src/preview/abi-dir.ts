import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import {
  AbiDecodeError,
  type AbiType,
  canonicalType,
  functionSelector,
  parseAbiType,
} from '../eth/abi.js';

/**
 * User-supplied ABIs from ~/.sigil/abi/*.json, so the preview can name
 * functions on the user's own contracts ("setFee(fee=30)" instead of
 * "unknown function 0x69fe0e2d").
 *
 * Each file is either a bare ABI array or a Foundry/Hardhat artifact
 * `{ "abi": [...] }`. Loading is presentation-only and therefore never
 * fatal: a malformed file is skipped and recorded in `loadWarnings`, which
 * the preview text surfaces (`abi: skipped <file>: <reason>`) so the user
 * notices instead of silently getting less detail.
 *
 * Files are read once at sigil-mcp boot, in sorted filename order; the first
 * definition of a selector wins, so a collision resolves deterministically.
 * The directory sits inside ~/.sigil (0700) — whoever can write it can also
 * write the policy files, so it carries no trust the policy doesn't.
 */

export interface AbiInput {
  name: string;
  /** Canonical type ("(address,uint256)[]" for tuple[]). */
  type: string;
  abiType: AbiType;
}

export interface AbiFunction {
  selector: string;
  signature: string;
  name: string;
  inputs: AbiInput[];
  /** File the definition came from. */
  source: string;
}

/** Artifacts carry bytecode and can be large; anything past this is skipped. */
const MAX_ABI_FILE_BYTES = 16 * 1024 * 1024;

export class AbiRegistry {
  readonly #bySelector: ReadonlyMap<string, AbiFunction>;
  readonly loadWarnings: readonly string[];

  private constructor(bySelector: Map<string, AbiFunction>, warnings: string[]) {
    this.#bySelector = bySelector;
    this.loadWarnings = Object.freeze([...warnings]);
  }

  static empty(): AbiRegistry {
    return new AbiRegistry(new Map(), []);
  }

  /**
   * Load every *.json in `dir`. A missing directory is an empty registry;
   * an unreadable one is an empty registry with a warning.
   */
  static fromDir(dir: string): AbiRegistry {
    let names: string[];
    try {
      names = readdirSync(dir)
        .filter((f) => f.endsWith('.json'))
        .sort();
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return AbiRegistry.empty();
      return new AbiRegistry(new Map(), [
        `abi: cannot read ${dir}: ${(err as NodeJS.ErrnoException).code ?? (err as Error).message}`,
      ]);
    }
    const files: { name: string; text: string }[] = [];
    const warnings: string[] = [];
    for (const name of names) {
      const path = join(dir, name);
      try {
        if (statSync(path).size > MAX_ABI_FILE_BYTES) {
          warnings.push(`abi: skipped ${name}: larger than ${MAX_ABI_FILE_BYTES} bytes`);
          continue;
        }
        files.push({ name, text: readFileSync(path, 'utf8') });
      } catch (err) {
        warnings.push(
          `abi: skipped ${name}: ${(err as NodeJS.ErrnoException).code ?? (err as Error).message}`,
        );
      }
    }
    const reg = AbiRegistry.fromSources(files);
    return new AbiRegistry(new Map(reg.#bySelector), [...warnings, ...reg.loadWarnings]);
  }

  /** Build from in-memory file contents (tests, and fromDir's second half). */
  static fromSources(files: readonly { name: string; text: string }[]): AbiRegistry {
    const map = new Map<string, AbiFunction>();
    const warnings: string[] = [];
    for (const { name, text } of files) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        warnings.push(`abi: skipped ${name}: invalid JSON`);
        continue;
      }
      const abi = Array.isArray(parsed)
        ? parsed
        : isObject(parsed) && Array.isArray(parsed['abi'])
          ? (parsed['abi'] as unknown[])
          : null;
      if (abi === null) {
        warnings.push(`abi: skipped ${name}: expected an ABI array or an artifact with "abi"`);
        continue;
      }
      let unsupported = 0;
      let badName: string | undefined;
      const fns: Omit<AbiFunction, 'source'>[] = [];
      for (const item of abi) {
        if (!isObject(item)) continue;
        // `type` defaults to "function" per the Solidity JSON ABI spec.
        if (item['type'] !== undefined && item['type'] !== 'function') continue;
        try {
          fns.push(parseFunction(item));
        } catch (err) {
          if (err instanceof AbiNameError) {
            badName = err.message;
            break;
          }
          unsupported++;
        }
      }
      // Names are rendered into the preview the human reads; a file that
      // smuggles anything but identifiers in them is refused whole.
      if (badName !== undefined) {
        warnings.push(`abi: skipped ${name}: ${badName}`);
        continue;
      }
      for (const f of fns) if (!map.has(f.selector)) map.set(f.selector, { ...f, source: name });
      if (unsupported > 0) {
        warnings.push(
          `abi: ${name}: skipped ${unsupported} function${unsupported === 1 ? '' : 's'} with unsupported or malformed types`,
        );
      }
    }
    return new AbiRegistry(map, warnings);
  }

  lookup(selector: string): AbiFunction | undefined {
    return this.#bySelector.get(selector.toLowerCase());
  }

  get size(): number {
    return this.#bySelector.size;
  }
}

/** Solidity identifier, bounded. Anything else is refused, not rendered. */
const IDENT_RE = /^[A-Za-z_$][A-Za-z0-9_$]{0,63}$/;

class AbiNameError extends Error {}

/** An optional parameter/component name: empty or an identifier. */
function checkParamName(v: unknown, where: string): void {
  if (v === undefined || v === '') return;
  if (typeof v !== 'string' || !IDENT_RE.test(v)) {
    throw new AbiNameError(`invalid identifier ${clip(v)} in ${where}`);
  }
}

function clip(v: unknown): string {
  const s = JSON.stringify(typeof v === 'string' ? v : String(v)) ?? '';
  return s.length > 40 ? s.slice(0, 40) + '…' : s;
}

function parseFunction(item: Record<string, unknown>): Omit<AbiFunction, 'source'> {
  const name = item['name'];
  if (typeof name !== 'string' || !IDENT_RE.test(name)) {
    throw new AbiNameError(`invalid function name ${clip(name)}`);
  }
  const rawInputs = item['inputs'] ?? [];
  if (!Array.isArray(rawInputs)) throw new AbiDecodeError('inputs');
  const inputs: AbiInput[] = rawInputs.map((inp, i) => {
    if (!isObject(inp)) throw new AbiDecodeError('input');
    checkParamName(inp['name'], `${name}()`);
    const type = jsonType(inp, 0);
    const abiType = parseAbiType(type);
    const nm = typeof inp['name'] === 'string' && inp['name'] !== '' ? inp['name'] : `arg${i}`;
    return { name: nm, type: canonicalType(abiType), abiType };
  });
  const signature = `${name}(${inputs.map((i) => i.type).join(',')})`;
  return { selector: functionSelector(signature), signature, name, inputs };
}

/** JSON ABI param → canonical type string, expanding `tuple…` via components. */
function jsonType(p: Record<string, unknown>, depth: number): string {
  if (depth > 32) throw new AbiDecodeError('nesting');
  const t = p['type'];
  if (typeof t !== 'string') throw new AbiDecodeError('type');
  if (!t.startsWith('tuple')) return t;
  const comps = p['components'];
  if (!Array.isArray(comps)) throw new AbiDecodeError('components');
  const inner = comps.map((c) => {
    if (!isObject(c)) throw new AbiDecodeError('component');
    checkParamName(c['name'], 'a tuple component');
    return jsonType(c, depth + 1);
  });
  return `(${inner.join(',')})${t.slice('tuple'.length)}`;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
