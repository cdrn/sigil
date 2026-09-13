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

test('STRICT_TEMPLATE: typed-data allowlists present and empty; window caps commented out', () => {
  const p = parsePolicy(STRICT_TEMPLATE);
  equal(p.typedDataVerifyingContracts.length, 0);
  equal(p.typedDataPrimaryTypes.length, 0);
  equal(p.maxValuePerHourWei, undefined);
  equal(p.maxValuePerDayWei, undefined);
  equal(p.svmMaxLamportsPerHour, undefined);
  equal(p.svmMaxLamportsPerDay, undefined);
  ok(/# max_value_per_hour_wei/.test(STRICT_TEMPLATE));
  ok(/# svm_max_lamports_per_day/.test(STRICT_TEMPLATE));
  ok(/typed_data_verifying_contracts = \[\]/.test(STRICT_TEMPLATE));
});

test('PERMISSIVE_TEMPLATE: mentions the window caps (the one rule that applies there) but sets none', () => {
  const p = parsePolicy(PERMISSIVE_TEMPLATE);
  equal(p.mode, 'permissive');
  equal(p.maxValuePerDayWei, undefined);
  ok(/# max_value_per_day_wei/.test(PERMISSIVE_TEMPLATE));
  // Uncommenting the examples yields a valid policy.
  const uncommented = PERMISSIVE_TEMPLATE.replace(
    /^# (max_value_per_(hour|day)_wei|svm_max_lamports_per_(hour|day))/gm,
    '$1',
  );
  const q = parsePolicy(uncommented);
  equal(q.maxValuePerHourWei, 10n ** 17n);
  equal(q.maxValuePerDayWei, 10n ** 18n);
  equal(q.svmMaxLamportsPerHour, 100_000_000n);
  equal(q.svmMaxLamportsPerDay, 1_000_000_000n);
});
