import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildFinding,
  buildFindings,
  deriveSeverity,
  summariseBySeverity,
  SEVERITY,
} from './finding-taxonomy.js';

/**
 * Severity used to come from a Gemini prompt, so the same run could produce
 * different severities on different days and nothing could be filtered or
 * compared. These tests pin the rule that a FAIL is a gap and a PASS is not —
 * getting that backwards inverts the meaning of the whole report.
 */

test('a failed tamper technique is a critical gap', () => {
  const s = deriveSeverity('disable_etw', 'FAIL', 'ETW providers disabled');
  assert.equal(s, SEVERITY.CRITICAL);
});

test('a resisted technique is low severity regardless of how severe it would be', () => {
  // AMSI bypass succeeding would be critical, but PASS means the EDR stopped
  // it. Reporting PASS at CRITICAL would invert the report's meaning.
  assert.equal(deriveSeverity('disable_amsi', 'PASS', 'AMSI patch blocked'), SEVERITY.LOW);
  assert.equal(deriveSeverity('unload_driver', 'BLOCKED_BY_EDR', 'driver protected'), SEVERITY.LOW);
});

test('informational acknowledgements are not findings', () => {
  assert.equal(deriveSeverity('performance', 'INFO', 'CPU 11%'), SEVERITY.INFO);
  assert.equal(deriveSeverity('performance', 'SKIPPED', 'no consent'), SEVERITY.INFO);
});

test('inconclusive outcomes are medium, not a gap', () => {
  // A timeout says nothing about whether the EDR would have resisted. Calling
  // it a critical gap is as wrong as calling it a pass.
  assert.equal(deriveSeverity('lolbin', 'TIMEOUT', 'exceeded 45s budget'), SEVERITY.MEDIUM);
  assert.equal(deriveSeverity('network', 'ERROR', 'probe failed'), SEVERITY.MEDIUM);
});

test('a FAIL whose own prose says everything resisted is downgraded', () => {
  // The real observed case: unload_driver reported FAIL while its detail said
  // "No EDR drivers could be stopped; all resisted". The specific evidence
  // must win over the coarse flag.
  const s = deriveSeverity('unload_driver', 'FAIL', 'No EDR drivers could be stopped; all resisted');
  assert.equal(s, SEVERITY.MEDIUM);
});

test('a finding carries observation, impact and recommendation', () => {
  const f = buildFinding({
    module_name: 'disable_amsi',
    action: 'FAIL',
    passed: false,
    detail: 'AMSI disabled via registry (PowerShell)',
    mitre: 'T1562.001',
    recorded_at: '2026-10-15T10:36:41.000Z',
  }, 1);

  assert.equal(f.severity, SEVERITY.CRITICAL);
  assert.equal(f.mitre, 'T1562.001');
  assert.equal(f.observation, 'AMSI disabled via registry (PowerShell)');
  assert.ok(f.impact.length > 40, 'impact should be substantive');
  assert.ok(f.recommendation.includes('AMSIEnabled'), 'recommendation should name the control');
  assert.equal(f.isFinding, true);
});

test('a module that skipped the test is not reported as a gap', () => {
  // Observed on a real run: the reboot module stores action=FAIL while its
  // detail reads "SKIPPED — Reboot not permitted". Scoring that HIGH invents a
  // finding for a module that never executed.
  const f = buildFinding({
    module_name: 'reboot',
    action: 'FAIL',
    passed: false,
    detail: 'SKIPPED — Reboot not permitted',
    mitre: 'T1547.001',
  }, 1);

  assert.equal(f.severity, SEVERITY.INFO);
  assert.equal(f.isFinding, false);
});

test('an INFO-prefixed detail is treated as an acknowledgement', () => {
  assert.equal(deriveSeverity('performance', 'FAIL', 'INFO — baseline sample only'), SEVERITY.INFO);
  assert.equal(deriveSeverity('network', 'FAIL', 'not applicable: no egress to test'), SEVERITY.INFO);
});

test('an unknown MITRE id is reported as absent rather than passed through', () => {
  const f = buildFinding({ module_name: 'network', action: 'PASS', passed: true, detail: 'blocked', mitre: 'Unknown' }, 1);
  assert.equal(f.mitre, null);
});

test('findings sort by severity, most severe first, and renumber', () => {
  const findings = buildFindings([
    { module_name: 'performance', action: 'PASS', passed: true, detail: 'CPU ok', recorded_at: '2026-10-15T10:00:00Z' },
    { module_name: 'disable_etw', action: 'FAIL', passed: false, detail: 'ETW disabled', recorded_at: '2026-10-15T10:00:01Z' },
    { module_name: 'lolbin', action: 'PASS', passed: true, detail: 'blocked', recorded_at: '2026-10-15T10:00:02Z' },
    { module_name: 'identity', action: 'FAIL', passed: false, detail: 'no alert raised', recorded_at: '2026-10-15T10:00:03Z' },
  ]);

  assert.deepEqual(findings.map(f => f.severity), [
    SEVERITY.CRITICAL, SEVERITY.HIGH, SEVERITY.LOW, SEVERITY.LOW,
  ]);
  assert.deepEqual(findings.map(f => f.index), [1, 2, 3, 4]);
});

test('severity counts exclude nothing but are accurate', () => {
  const findings = buildFindings([
    { module_name: 'disable_etw', action: 'FAIL', passed: false, detail: 'ETW disabled' },
    { module_name: 'identity', action: 'FAIL', passed: false, detail: 'no alert' },
    { module_name: 'lolbin', action: 'PASS', passed: true, detail: 'blocked' },
  ]);
  const counts = summariseBySeverity(findings);
  assert.equal(counts.CRITICAL, 1);
  assert.equal(counts.HIGH, 1);
  assert.equal(counts.LOW, 1);
  assert.equal(counts.MEDIUM, 0);
});

test('an unrecognised module still produces a usable finding', () => {
  const f = buildFinding({ module_name: 'brand_new_module', action: 'FAIL', passed: false, detail: 'something happened' }, 1);
  assert.equal(f.severity, SEVERITY.MEDIUM);
  assert.ok(f.impact.length > 0);
  assert.ok(f.recommendation.length > 0);
});