import { parseArgs, type ParseArgsConfig } from 'node:util';

/**
 * Tiny CLI arg-parsing wrapper around node:util.parseArgs.
 * We support subcommands by consuming the first positional, then re-parsing
 * the remainder with subcommand-specific options.
 */

export interface ParsedSubcommand {
  command: string;
  positionals: string[];
  options: Record<string, string | boolean>;
}

// We don't want to leak parseArgs' deep generic shape; users of SubcommandSpec
// just pass a plain options record.
export type OptionDef =
  { type: 'string'; short?: string; multiple?: boolean } | { type: 'boolean'; short?: string };

export interface SubcommandSpec {
  options?: Record<string, OptionDef>;
}

export function parseSubcommand(
  argv: string[],
  specs: Record<string, SubcommandSpec>,
): ParsedSubcommand {
  if (argv.length === 0) {
    throw new ArgsError('expected a subcommand');
  }
  const [head, ...rest] = argv;
  if (head === undefined) throw new ArgsError('expected a subcommand');
  const spec = specs[head];
  if (!spec) {
    throw new ArgsError(
      `unknown subcommand "${head}"; expected one of: ${Object.keys(specs).join(', ')}`,
    );
  }
  let parsed;
  try {
    parsed = parseArgs({
      args: rest,
      allowPositionals: true,
      options: spec.options ?? {},
    } as ParseArgsConfig);
  } catch (err) {
    throw new ArgsError(`parsing "${head}": ${(err as Error).message}`);
  }
  return {
    command: head,
    positionals: parsed.positionals,
    options: parsed.values as Record<string, string | boolean>,
  };
}

export class ArgsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ArgsError';
  }
}
