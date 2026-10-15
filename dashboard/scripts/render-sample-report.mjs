/**
 * Renders a sample standalone report to disk for visual inspection.
 *
 * The dashboard's own HTML export is produced in the browser, so this is how
 * the output gets reviewed without clicking through the UI. Uses the same
 * renderer and a payload shaped exactly like Reports.jsx produces.
 *
 * Usage: node scripts/render-sample-report.mjs [outfile]
 */
import fs from 'fs';
import path from 'path';
import { renderStandaloneHtml } from '../src/report-template.js';

const out = process.argv[2]
  || path.join('C:\\Users\\DELL\\AppData\\Local\\Temp\\opencode\\sample-report.html');

const payload = {
  agent: 'DESKTOP-L07M1SS',
  assessment_id: '4cb16b66-941d-415b-9099-139ad263feb8',
  scope: {
    profile: 'rapid',
    test_types: ['blackbox'],
    modules_requested: ['antitamper', 'disable_etw', 'disable_amsi', 'identity'],
    modules_tested: ['disable_etw', 'disable_amsi', 'modify_registry_policies', 'identity', 'malware', 'lolbin'],
    target_vendors: ['Microsoft Defender'],
    vendor_detected: 'Microsoft Defender',
    started_at: '2026-10-15T09:34:49.000Z',
    completed_at: '2026-10-15T09:41:12.000Z',
    status: 'completed',
    score: 46,
  },
  summary: { totalModules: 6, passedModules: 2, failedModules: 4, totalTampers: 0, score: 46 },
  deployment_integrity: [
    { result: 'AGENT_RECOVERED', module: 'antitamper', killed_at: '2026-10-15T09:36:02.000Z', recovered_at: '2026-10-15T09:36:14.000Z' },
  ],
  module_results: [
    { module: 'disable_etw', result: 'FAIL', severity: 'CRITICAL', is_finding: true, detail: 'ETW providers disabled: Kernel Process ETW provider disabled; Kernel Image Load ETW provider disabled; Kernel Thread ETW provider disabled', impact: 'Disabling the kernel process, image-load and thread autologgers blinds the EDR to process creation and image loading — the two signals most detection logic depends on.', recommendation: 'Enforce ETW provider integrity with a hardened CSP / WDAC policy that denies write access to the Autologger keys, and alert on changes to the Start value.', mitre: 'T1562.002', duration_ms: 10, timestamp: '2026-10-15T09:35:02.000Z' },
    { module: 'disable_amsi', result: 'FAIL', severity: 'CRITICAL', is_finding: true, detail: 'AMSI disabled via registry (PowerShell)', impact: 'With AMSI disabled, malicious PowerShell is no longer inspected at execution time.', recommendation: 'Re-enforce AMSI through policy and alert on any process writing those values.', mitre: 'T1562.001', duration_ms: 32, timestamp: '2026-10-15T09:35:03.000Z' },
    { module: 'modify_registry_policies', result: 'FAIL', severity: 'CRITICAL', is_finding: true, detail: 'Registry policies modified: Disable Windows Defender Anti-Spyware; Disable Windows Defender Real-time Monitoring; Disable Windows Firewall (Domain Profile)', impact: 'Disabling real-time protection, behaviour monitoring and the firewall via policy keys removes layered controls simultaneously.', recommendation: 'Baseline the HKLM\\SOFTWARE\\Policies security keys and alert on drift.', mitre: 'T1112', duration_ms: 138, timestamp: '2026-10-15T09:35:12.000Z' },
    { module: 'identity', result: 'FAIL', severity: 'HIGH', is_finding: true, detail: 'FAIL — No alert raised for repeated failed logins', impact: 'Repeated failed authentication attempts produced no alert, so password spraying would pass unnoticed.', recommendation: 'Enable failed-logon auditing thresholds and alert on spray patterns.', mitre: 'T1110.003', duration_ms: 2225, timestamp: '2026-10-15T09:36:20.000Z' },
    { module: 'malware', result: 'PASS', severity: 'LOW', is_finding: false, detail: 'PASS — EICAR execution blocked by endpoint protection', impact: 'omitted', recommendation: 'omitted', mitre: 'T1204.002', duration_ms: 17188, timestamp: '2026-10-15T09:38:44.000Z' },
    { module: 'lolbin', result: 'PASS', severity: 'LOW', is_finding: false, detail: 'PASS — LOLBin execution blocked', impact: 'omitted', recommendation: 'omitted', mitre: 'T1059.001', duration_ms: 12004, timestamp: '2026-10-15T09:39:20.000Z' },
  ],
};

const html = renderStandaloneHtml(payload, { generatedAt: '2026-10-15T10:00:00.000Z' });
fs.writeFileSync(out, html, 'utf8');
console.log(`wrote ${out} (${(html.length / 1024).toFixed(1)} KB)`);