/**
 * Finding taxonomy: turns a raw result row into a structured finding with a
 * deterministic severity, impact and recommendation.
 *
 * Why this exists: the GTCO/consulting report format expects every finding to
 * carry a severity plus Observation / Impact / Recommendation. The only place
 * that structure existed was a Gemini prompt, so severities were whatever the
 * model felt like writing for a given run — not reproducible, not filterable,
 * and not comparable between assessments.
 *
 * Severity here is derived from what the module actually did and what the
 * endpoint actually reported, never guessed:
 *
 *   CRITICAL  the EDR did not resist a high-consequence tamper technique
 *   HIGH      the EDR did not resist the technique, lower consequence
 *   MEDIUM    inconclusive — the module timed out or errored
 *   LOW       the EDR resisted (PASS); recorded for completeness
 *   INFO      not a verdict (INFO/SKIPPED acknowledgements)
 */

export const SEVERITY = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  INFO: 'INFO',
};

/** Results that are acknowledgements, not verdicts on a control. */
const NON_VERDICT = new Set(['INFO', 'SKIPPED', 'FIXED', 'AGENT_RECOVERED']);

/** Results that mean the EDR successfully resisted the attempt. */
const RESISTED = new Set(['PASS', 'BLOCKED', 'BLOCKED_BY_EDR']);

/**
 * Per-module narrative. `impact` explains the risk to the estate if this is
 * left unaddressed; `recommendation` is the concrete control to deploy.
 *
 * `baseSeverity` is the severity when the technique SUCCEEDED. A module whose
 * technique is resisted drops to LOW regardless.
 */
const MODULE_GUIDANCE = {
  disable_etw: {
    title: 'ETW telemetry providers disabled',
    baseSeverity: SEVERITY.CRITICAL,
    impact:
      'Disabling the kernel process, image-load and thread autologgers blinds the EDR to process creation and image loading — the two signals most detection logic depends on. Subsequent malicious activity can execute without generating the telemetry that would have flagged it, and the blind spot is invisible to the EDR by construction.',
    recommendation:
      'Enforce ETW provider integrity with a hardened CSP / Windows Defender Application Control policy that denies write access to HKLM\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger for non-elevated processes, and alert on changes to the Start value of any autologger key via a registry auditing GPO.',
  },
  disable_amsi: {
    title: 'AMSI and PowerShell script-block logging disabled',
    baseSeverity: SEVERITY.CRITICAL,
    impact:
      'With AMSI disabled, malicious PowerShell — including obfuscated and in-memory script blocks — is no longer inspected at execution time. Combined with disabled script-block logging, an operator gains an interactive shell with neither content inspection nor an audit trail, which is the standard first stage of fileless and living-off-the-land attacks.',
    recommendation:
      'Re-enforce AMSI through policy (HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging = Enabled and AMSIEnabled = 1), enforce Constrained Language Mode or AppLocker/WDAC for PowerShell, and alert on any process writing those values.',
  },
  disable_etw_tamper: {
    title: 'ETW trace output redirected',
    baseSeverity: SEVERITY.HIGH,
    impact:
      'Redirecting autologger trace paths prevents telemetry being written even though the providers themselves remain enabled. The EDR believes it is collecting data that is being discarded, so detection appears healthy while the evidence is lost.',
    recommendation:
      'Restrict write access to autologger LogFilePath entries, monitor for modifications to those values, and validate on a schedule that expected trace files are actually being written.',
  },
  unload_driver: {
    title: 'EDR kernel driver unload attempted',
    baseSeverity: SEVERITY.CRITICAL,
    impact:
      'A successful driver stop disables the EDR kernel callback that enforces process, registry and file monitoring. The host continues to appear protected in the console while all kernel-level enforcement is offline.',
    recommendation:
      'Enforce driver ACLs denying SERVICE_STOP to non-administrative principals, enable tamper protection, and alert on any attempt to stop or tamper with the EDR driver service.',
  },
  modify_registry_policies: {
    title: 'Security policy registry keys modified',
    baseSeverity: SEVERITY.CRITICAL,
    impact:
      'Disabling real-time protection, behaviour monitoring, the firewall, UAC, Windows Update and SmartScreen via policy registry keys removes layered controls simultaneously. An attacker who can write these keys can silently reduce the endpoint to an undefended state that still reports as compliant.',
    recommendation:
      'Baseline the HKLM\\SOFTWARE\\Policies security keys and alert on drift, deploy the same values through a GPO with a locked-down ACL that denies write to non-admin processes, and enable Defender Tamper Protection.',
  },
  malware: {
    title: 'Malicious test file execution',
    baseSeverity: SEVERITY.HIGH,
    impact:
      'A benign EICAR test file was executed rather than blocked, indicating the endpoint prevention stack did not stop a known-malicious payload at execution.',
    recommendation:
      'Confirm real-time protection and cloud-delivered protection are enabled and current, verify no exclusions cover the SystemTemp path, and re-test.',
  },
  lolbin: {
    title: 'Living-off-the-land binary abuse',
    baseSeverity: SEVERITY.HIGH,
    impact:
      'A signed Microsoft binary executed without detection. LOLBin abuse is a primary evasion technique because the binary is trusted and requires no malware to be delivered.',
    recommendation:
      'Enable script block and command line auditing for signed binaries, apply WDAC/AppLocker rules restricting LOLBin execution from user-writable paths, and tune detection for the specific binaries observed.',
  },
  network: {
    title: 'Outbound command-and-control traffic',
    baseSeverity: SEVERITY.HIGH,
    impact:
      'The endpoint initiated an outbound connection that was not blocked, indicating network egress control does not cover command-and-control infrastructure.',
    recommendation:
      'Enforce egress filtering to deny unapproved destinations, deploy firewall and proxy-based TLS inspection, and validate that agent traffic blocking rules are active.',
  },
  identity: {
    title: 'Credential attack not detected',
    baseSeverity: SEVERITY.HIGH,
    impact:
      'Repeated failed authentication attempts produced no alert, so password spraying and brute-force activity would pass unnoticed. Credential stuffing frequently precedes lateral movement.',
    recommendation:
      'Enable failed-logon auditing thresholds and alert on spray patterns (many accounts, one source), route security events to the SIEM, and confirm the endpoint is actually reporting authentication events.',
  },
  antitamper: {
    title: 'Agent tampering not detected',
    baseSeverity: SEVERITY.HIGH,
    impact:
      'Attempts to tamper with or remove security tooling were not detected or blocked, indicating the endpoint lacks effective self-protection.',
    recommendation:
      'Enable tamper protection and self-protection on the EDR agent, lock down the agent service and binary ACLs, and alert on unexpected service stops or binary deletion.',
  },
  falsepositive: {
    title: 'Alert noise on benign activity',
    baseSeverity: SEVERITY.LOW,
    impact:
      'Benign administrative activity generated alerts, which contributes to analyst fatigue and increases the risk of true positives being dismissed.',
    recommendation:
      'Tune or suppress the specific benign detections and review alert volume in the detection engineering cycle.',
  },
  performance: {
    title: 'Endpoint resource usage during assessment',
    baseSeverity: SEVERITY.INFO,
    impact:
      'Host CPU and memory utilisation were sampled to establish whether the assessment itself degraded the endpoint. This is context for interpreting other results, not a security gap.',
    recommendation:
      'No action required; use the captured baseline when comparing future runs.',
  },
  reboot: {
    title: 'Boot-time protection gap',
    baseSeverity: SEVERITY.HIGH,
    impact:
      'A measurable window exists after boot and before the EDR agent is fully operational, during which malicious persistence can execute unobserved.',
    recommendation:
      'Deploy a boot-start driver or ELAM-based early-launch configuration, and shorten the pre-agent window by enabling the service to start on boot with protected service flags.',
  },
};

const GENERIC = {
  title: 'Assessment finding',
  baseSeverity: SEVERITY.MEDIUM,
  impact:
    'The endpoint did not resist this technique. The precise consequence depends on what the technique enables on this host, which should be established from the surrounding findings in this assessment.',
  recommendation:
    'Review the observation and determine which control should have prevented this. Re-test after remediation to confirm the control now resists the technique.',
};

/**
 * deriveSeverity decides the severity from the recorded verdict.
 *
 * The important distinction: a FAIL means the EDR did NOT stop the technique,
 * which is a gap and inherits the module's base severity. A PASS means the EDR
 * resisted, which is the desired outcome and is LOW regardless of how severe
 * the technique would have been. Inconclusive outcomes (TIMEOUT, ERROR) are
 * MEDIUM because they say nothing about the EDR either way — reporting them as
 * a gap would be as wrong as reporting them as a pass.
 */
export function deriveSeverity(moduleName, result, detail = '') {
  if (!result || NON_VERDICT.has(result)) return SEVERITY.INFO;

  if (RESISTED.has(result)) return SEVERITY.LOW;

  if (result === 'TIMEOUT' || result === 'ERROR') {
    return SEVERITY.MEDIUM;
  }

  const guidance = MODULE_GUIDANCE[moduleName] || GENERIC;

  // The coarse `action` flag regularly disagrees with the module's own detail.
  // A module that prefixed its detail with SKIPPED or INFO did not test the
  // control — reporting it as a gap invents a finding. Observed in practice: the
  // reboot module records action=FAIL while its detail reads "SKIPPED — Reboot
  // not permitted", which would otherwise be scored HIGH.
  if (/^\s*(SKIPPED|INFO|NOT APPLICABLE)\b/i.test(detail)) {
    return SEVERITY.INFO;
  }

  // A module that reported "all resisted" in prose has contradicted its own
  // FAIL verdict. Trust the specific evidence over the coarse flag, and say so
  // at MEDIUM rather than claiming a critical gap that did not happen.
  if (/all resisted|no .* could be|could be stopped; all/i.test(detail)) {
    return SEVERITY.MEDIUM;
  }

  return guidance.baseSeverity;
}

/**
 * buildFinding turns one stored result row into the GTCO finding structure.
 *
 * `row` is a results-table row: module_name, action, passed, detail, mitre,
 * recorded_at, elapsed_ms.
 */
export function buildFinding(row, index) {
  const moduleName = row.module_name || 'unknown';
  const detail = row.detail || '';

  // results rows store the verdict in `action` (PASS/FAIL/TIMEOUT/...) and
  // mirror it in `passed`; prefer the richer string.
  const result = row.action || (row.passed === true ? 'PASS' : row.passed === false ? 'FAIL' : 'INFO');

  const guidance = MODULE_GUIDANCE[moduleName] || GENERIC;
  const severity = deriveSeverity(moduleName, result, detail);

  const observation = detail || `${guidance.title}: ${result}`;

  return {
    index,
    module: moduleName,
    title: guidance.title,
    action: row.action || '',
    mitre: row.mitre && row.mitre !== 'Unknown' ? row.mitre : null,
    result,
    severity,
    isFinding: severity === SEVERITY.CRITICAL || severity === SEVERITY.HIGH || severity === SEVERITY.MEDIUM,
    executedAt: row.recorded_at || row.recorded_ts || null,
    elapsedMs: row.elapsed_ms != null ? Number(row.elapsed_ms) : null,
    observation,
    impact: guidance.impact,
    recommendation: guidance.recommendation,
  };
}

/** buildFindings converts a whole result set, ordered by severity then time. */
export function buildFindings(rows) {
  const severityRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

  const findings = rows.map((row, i) => buildFinding(row, i + 1));

  findings.sort((a, b) => {
    const ra = severityRank[a.severity];
    const rb = severityRank[b.severity];
    if (ra !== rb) return ra - rb;
    return String(a.executedAt || '').localeCompare(String(b.executedAt || ''));
  });

  // Renumber after sorting so the displayed index follows severity order.
  findings.forEach((f, i) => { f.index = i + 1; });

  return findings;
}

/** summarise counts findings by severity for the report header. */
export function summariseBySeverity(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) {
    if (counts[f.severity] !== undefined) counts[f.severity] += 1;
  }
  return counts;
}

export { MODULE_GUIDANCE };