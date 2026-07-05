import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import {
  parsePolicy,
  PERMISSIVE_TEMPLATE,
  policyTemplate,
  STRICT_TEMPLATE,
} from '../../src/policy/index.js';

test('PERMISSIVE_TEMPLATE parses back to a permissive policy', () => {
  const p = parsePolicy(PERMISSIVE_TEMPLATE);
  equal(p.mode, 'permissive');
});

test('STRICT_TEMPLATE parses back to a strict policy with conservative defaults', () => {
  const p = parsePolicy(STRICT_TEMPLATE);
  equal(p.mode, 'strict');
  // Conservative: chain_ids has mainnet only, no allow_to, no value, no selectors,
  // no message/typed-data — user opts in explicitly.
  equal(p.maxValueWei, 0n);
  equal(p.allowTo.length, 0);
  equal(p.allowedSelectors.length, 0);
  equal(p.allowContractCreation, false);
  equal(p.allowMessageSigning, false);
  equal(p.allowTypedData, false);
});

test('policyTemplate("permissive") returns PERMISSIVE_TEMPLATE', () => {
  equal(policyTemplate('permissive'), PERMISSIVE_TEMPLATE);
});

test('policyTemplate("strict") returns STRICT_TEMPLATE', () => {
  equal(policyTemplate('strict'), STRICT_TEMPLATE);
});

test('strict template mentions SIWE / OpenSea / Permit in comments', () => {
  ok(/Sign-In With Ethereum/.test(STRICT_TEMPLATE));
  ok(/OpenSea|Permit/.test(STRICT_TEMPLATE));
});
