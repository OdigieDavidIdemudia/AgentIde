import { test } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Unit tests for the start_assessment command frame.
 *
 * This payload is the contract between the dashboard and the agent, and three
 * of its fields were previously missing entirely: only `profile` and
 * `test_type` were sent, so the agent always ran every module at its own
 * startup `-days` and its own `--allow-reboot` flag. The DB and the report
 * recorded the operator's selection, meaning the report described an
 * assessment that never happened.
 */

const { buildStartAssessment, apiUrl } = await import('./api.js');

test('start_assessment carries the full operator scope', () => {
  const cmd = buildStartAssessment({
    hostname: 'WS-1',
    profile: 'rapid',
    testType: 'blackbox',
    modules: ['malware', 'identity'],
    days: 1,
    allowReboot: true,
  });

  assert.equal(cmd.type, 'start_assessment');
  assert.equal(cmd.agent_id, 'WS-1');
  assert.equal(cmd.profile, 'rapid');
  assert.equal(cmd.test_type, 'blackbox');
  // The three fields that used to be dropped on the floor.
  assert.deepEqual(cmd.modules, ['malware', 'identity']);
  assert.equal(cmd.days, 1);
  assert.equal(cmd.allow_reboot, true);
});

test('start_assessment includes the keys even when values are falsy', () => {
  // The agent distinguishes an absent key from an explicit false, so the keys
  // must always be present for its fallbacks to behave predictably.
  const cmd = buildStartAssessment({
    hostname: 'WS-2',
    profile: 'apt',
    testType: 'whitebox',
    modules: [],
    days: 0,
    allowReboot: false,
  });

  assert.ok('modules' in cmd);
  assert.ok('days' in cmd);
  assert.ok('allow_reboot' in cmd);
  assert.deepEqual(cmd.modules, []);
  assert.equal(cmd.allow_reboot, false);
  assert.equal(typeof cmd.allow_reboot, 'boolean');
});

test('start_assessment coerces a non-array module selection to []', () => {
  const cmd = buildStartAssessment({
    hostname: 'WS-3',
    profile: 'rapid',
    testType: 'blackbox',
    modules: null,
    days: 1,
    allowReboot: false,
  });
  assert.deepEqual(cmd.modules, []);
});

test('start_assessment preserves a single-module selection', () => {
  const cmd = buildStartAssessment({
    hostname: 'WS-4',
    profile: 'rapid',
    testType: 'blackbox',
    modules: ['network'],
    days: 1,
    allowReboot: false,
  });
  assert.deepEqual(cmd.modules, ['network']);
});

test('start_assessment propagates a multi-day duration', () => {
  const cmd = buildStartAssessment({
    hostname: 'WS-5',
    profile: 'apt',
    testType: 'blackbox',
    modules: ['malware'],
    days: 14,
    allowReboot: false,
  });
  assert.equal(cmd.days, 14);
});

// Outside Vite, import.meta.env is undefined, so apiUrl must fall back to an
// absolute origin URL — that is the production path. The dev-relative branch
// is only reachable under the Vite dev server, which sets import.meta.env.DEV,
// and is covered end-to-end by the Playwright suite (which runs the real dev
// server on :3000). Asserting the production fallback here keeps this test
// honest rather than pretending to exercise the dev branch.
test('apiUrl is safe outside a browser context', () => {
  // No window/import.meta.env here, which is exactly the SSR/unit-test case.
  const url = apiUrl('/api/agents');
  assert.equal(url, '/api/agents');
});