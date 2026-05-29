import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import { homedir } from 'node:os';
import { expandTilde, globMatch, normalizePath } from '../../src/hooks/glob.js';

test('expandTilde: replaces leading ~', () => {
  equal(expandTilde('~/foo'), `${homedir()}/foo`);
  equal(expandTilde('~'), homedir());
  equal(expandTilde('no/tilde'), 'no/tilde');
  equal(expandTilde('/abs/path'), '/abs/path');
});

test('normalizePath: collapses repeated slashes and ../', () => {
  equal(normalizePath('/a//b/./c'), '/a/b/c');
  equal(normalizePath('/a/b/../c'), '/a/c');
  equal(normalizePath('a/b/../c'), 'a/c');
  equal(normalizePath('/'), '/');
});

test('globMatch: ** matches anything including separators', () => {
  ok(globMatch('/x/y/z/.sigil/keys/evm:bot.sigil', '**/.sigil/**'));
  ok(globMatch('.sigil/anything', '**/.sigil/**'));
});

test('globMatch: * does not match across separators', () => {
  ok(globMatch('foo.pem', '*.pem'));
  ok(!globMatch('a/foo.pem', '*.pem'));
});

test('globMatch: ? matches one non-separator char', () => {
  ok(globMatch('a.b', '?.?'));
  ok(!globMatch('a/b', '?.?'));
});

test('globMatch: literal special chars are escaped', () => {
  ok(globMatch('foo.bar', 'foo.bar'));
  ok(!globMatch('fooXbar', 'foo.bar'));
});

test('globMatch: tilde-prefixed pattern is expanded', () => {
  ok(globMatch(`${homedir()}/.sigil/keys/x`, '~/.sigil/**'));
});

test('globMatch: trailing /** matches subpaths', () => {
  ok(globMatch(`${homedir()}/.sigil/sock`, '~/.sigil/**'));
  ok(globMatch(`${homedir()}/.sigil/keys/evm:bot.sigil`, '~/.sigil/**'));
  // Standard glob: `dir/**` matches things INSIDE dir, not dir itself.
  // Reading a bare directory through Read wouldn't return file content anyway.
  equal(globMatch(`${homedir()}/.sigil`, '~/.sigil/**'), false);
});

test('globMatch: char class works', () => {
  ok(globMatch('a.x', '[ab].x'));
  ok(globMatch('b.x', '[ab].x'));
  ok(!globMatch('c.x', '[ab].x'));
});
