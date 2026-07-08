import { test } from 'node:test';
import { deepEqual, equal, ok, throws } from 'node:assert/strict';
import { ArgsError, parseSubcommand } from '../../src/cli/args.js';

const SPECS = {
  add: {
    options: {
      'key-file': { type: 'string' as const },
      'no-remove-source': { type: 'boolean' as const },
    },
  },
  list: { options: {} },
};

test('parseSubcommand: routes to the named subcommand', () => {
  const r = parseSubcommand(['add', 'evm:bot', '--key-file', './k'], SPECS);
  equal(r.command, 'add');
  deepEqual(r.positionals, ['evm:bot']);
  equal(r.options['key-file'], './k');
});

test('parseSubcommand: boolean flags default to absent', () => {
  const r = parseSubcommand(['add', 'evm:bot', '--key-file', './k'], SPECS);
  equal(r.options['no-remove-source'], undefined);
});

test('parseSubcommand: boolean flags can be set', () => {
  const r = parseSubcommand(['add', 'evm:bot', '--key-file', './k', '--no-remove-source'], SPECS);
  equal(r.options['no-remove-source'], true);
});

test('parseSubcommand: no args throws ArgsError', () => {
  throws(() => parseSubcommand([], SPECS), ArgsError);
});

test('parseSubcommand: unknown subcommand throws ArgsError listing valid ones', () => {
  let caught: Error | null = null;
  try {
    parseSubcommand(['nope'], SPECS);
  } catch (e) {
    caught = e as Error;
  }
  ok(caught instanceof ArgsError);
  ok(/add, list/.test(caught!.message));
});

test('parseSubcommand: surfaces parseArgs errors as ArgsError', () => {
  let caught: Error | null = null;
  try {
    parseSubcommand(['add', '--bogus-flag'], SPECS);
  } catch (e) {
    caught = e as Error;
  }
  ok(caught instanceof ArgsError);
});

test('parseSubcommand: positionals collected after flags', () => {
  const r = parseSubcommand(['list', 'extra', 'positionals'], SPECS);
  equal(r.command, 'list');
  deepEqual(r.positionals, ['extra', 'positionals']);
});
