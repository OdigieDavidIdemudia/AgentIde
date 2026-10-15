import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderStandaloneHtml, escapeHtml } from './report-template.js';

/**
 * The standalone HTML report is rendered from agent-supplied strings: module
 * names, detail text, vendor names and MITRE ids all originate on the
 * endpoint and are written into a file the operator opens locally. Treating
 * any of them as markup would be an injection sink, so escaping is the first
 * thing pinned here.
 */

const REPORT = {
  agent: 'WS-01',
  assessment_id: 'aaaaaaaa-1111-2222-3333-444444444444',
  scope: {
    profile: 'rapid',
    test_types: ['blackbox'],
    modules_tested: ['disable_etw', 'identity'],
    target_vendors: ['Microsoft Defender'],
    started_at: '2026-10-15T09:00:00.000Z',
    completed_at: '2026-10-15T09:10:00.000Z',
    status: 'completed',
    score: 62,
  },
  summary: { totalModules: 2, passedModules: 1, failedModules: 1, totalTampers: 0, score: 62 },
  deployment_integrity: [],
  module_results: [
    {
      module: 'disable_etw',
      result: 'FAIL',
      severity: 'CRITICAL',
      is_finding: true,
      detail: 'ETW providers disabled',
      impact: 'The EDR is blinded to process creation.',
      recommendation: 'Lock down the Autologger keys.',
      mitre: 'T1562.002',
      duration_ms: 10,
      timestamp: '2026-10-15T09:00:05.000Z',
    },
    {
      module: 'identity',
      result: 'PASS',
      severity: 'LOW',
      is_finding: false,
      detail: 'Alert raised',
      impact: 'Impact text should be omitted for a pass.',
      recommendation: 'Recommendation should be omitted for a pass.',
      mitre: 'T1110.003',
      duration_ms: 2240,
      timestamp: '2026-10-15T09:00:09.000Z',
    },
  ],
};

test('escapes every character that could open a tag or attribute', () => {
  assert.equal(escapeHtml('<img src=x onerror=alert(1)>'),
    '&lt;img src=x onerror=alert(1)&gt;');
  assert.equal(escapeHtml('a & b'), 'a &amp; b');
  assert.equal(escapeHtml('"quoted"'), '&quot;quoted&quot;');
  assert.equal(escapeHtml("it's"), 'it&#39;s');
});

test('escapes endpoint-supplied strings rather than interpolating them as markup', () => {
  const hostile = {
    ...REPORT,
    agent: '<script>alert(1)</script>',
    module_results: [
      {
        ...REPORT.module_results[0],
        module: '<img src=x onerror="alert(1)">',
        detail: '</style><script>alert(2)</script>',
      },
    ],
  };

  const html = renderStandaloneHtml(hostile);

  assert.ok(!html.includes('<script>alert(1)'), 'agent field must not be emitted raw');
  assert.ok(!html.includes('<img src=x'), 'module name must not be emitted raw');
  assert.ok(!html.includes('<script>alert(2)'), 'detail must not be emitted raw');
  assert.ok(html.includes('&lt;script&gt;'), 'hostile text should appear escaped');
});

test('produces a complete standalone document', () => {
  const html = renderStandaloneHtml(REPORT);
  assert.ok(html.startsWith('<!DOCTYPE html>'));
  assert.ok(html.includes('<html lang="en">'));
  assert.ok(html.trimEnd().endsWith('</html>'));
  // Self-contained: inline styles, no external stylesheet or script.
  assert.ok(html.includes('<style>'));
  assert.ok(!/<link[^>]+stylesheet/i.test(html), 'must not depend on an external stylesheet');
  assert.ok(!/<script/i.test(html), 'must contain no scripts at all');
});

test('is deterministic for the same payload', () => {
  const a = renderStandaloneHtml(REPORT, { generatedAt: '2026-10-15T10:00:00.000Z' });
  const b = renderStandaloneHtml(REPORT, { generatedAt: '2026-10-15T10:00:00.000Z' });
  assert.equal(a, b, 'two exports of one run must be byte-identical');
});

test('renders severity, observation, impact and recommendation per finding', () => {
  const html = renderStandaloneHtml(REPORT);
  assert.ok(html.includes('CRITICAL'));
  assert.ok(html.includes('LOW'));
  assert.ok(html.includes('Observation'));
  assert.ok(html.includes('The EDR is blinded to process creation.'));
  assert.ok(html.includes('Lock down the Autologger keys.'));
  assert.ok(html.includes('T1562.002'));
});

test('omits impact and recommendation for a finding that is not a gap', () => {
  const html = renderStandaloneHtml(REPORT);
  // The PASS row's narrative must not appear — reporting impact for a
  // technique the EDR stopped is misleading in a client-facing document.
  assert.ok(!html.includes('Impact text should be omitted for a pass.'));
  assert.ok(!html.includes('Recommendation should be omitted for a pass.'));
});

test('carries print pagination rules rather than hard-coded shadows', () => {
  const html = renderStandaloneHtml(REPORT);
  assert.ok(html.includes('@page'), 'needs @page for print sizing');
  assert.ok(html.includes('break-inside: avoid'), 'findings must not split across pages');
  assert.ok(html.includes('@media print'));
});

test('reports unrecorded scope as unknown rather than inventing it', () => {
  const html = renderStandaloneHtml({
    ...REPORT,
    scope: { ...REPORT.scope, target_vendors: [], profile: null, score: null },
    summary: { ...REPORT.summary, score: null },
  });
  assert.ok(html.includes('Not detected during this assessment'));
  assert.ok(html.includes('&mdash;'), 'missing values render as an em dash');
});

test('survives an empty findings set', () => {
  const html = renderStandaloneHtml({
    ...REPORT,
    module_results: [],
    summary: { totalModules: 0, passedModules: 0, failedModules: 0, score: null },
  });
  assert.ok(html.includes('No module results were recorded'));
  assert.ok(html.trimEnd().endsWith('</html>'));
});