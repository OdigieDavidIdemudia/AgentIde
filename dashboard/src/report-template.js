/**
 * Standalone HTML report renderer.
 *
 * Produces a single self-contained .html file from the same payload the Reports
 * screen shows — the same derived severities, the same impact and
 * recommendation text. Nothing here is model-generated, so two exports of the
 * same run are byte-identical.
 *
 * Design notes, and why they differ from the app theme on purpose:
 *
 * - The page is LIGHT. The app is dark-first, but a report gets printed, and a
 *   dark background wastes enormous ink, scans badly and photographs poorly in
 *   a review meeting. Screen fidelity loses to the artefact's actual purpose.
 * - Hard offset shadows are dropped for print. They are the app's identity, but
 *   a 5px black block repeated down every page edge reads as a printing defect.
 *   The colour language is kept: mint accent, the same severity hues.
 * - Type is normalised. The app's pixel display face (Silkscreen) is right for
 *   chrome but wrong for 400 words of impact prose, so body copy uses the mono
 *   pairing the app already loads.
 * - @page rules do the pagination work: A4, sane margins, and break-inside:
 *   avoid so a finding card is never split across a page boundary.
 * - There are no @page margin boxes (running heads, counter(page)). Those are a
 *   Paged.js extension and no shipping browser implements them, so a footer is
 *   done with a position:fixed element, which browsers repeat on every printed
 *   page. Page numbers come from the browser's own print dialog.
 *
 * Everything is escaped. Module names, details and vendor strings are supplied
 * by the endpoint, so treating them as markup would be an injection sink in a
 * file an operator opens locally.
 */

const SEVERITY_COLOURS = {
  CRITICAL: { bg: '#7f1d1d', fg: '#ffffff' },
  HIGH: { bg: '#b42318', fg: '#ffffff' },
  MEDIUM: { bg: '#9a6700', fg: '#ffffff' },
  LOW: { bg: '#1a7f37', fg: '#ffffff' },
  INFO: { bg: '#4b5563', fg: '#ffffff' },
};

const RESULT_COLOURS = {
  PASS: '#1a7f37',
  BLOCKED: '#1a7f37',
  BLOCKED_BY_EDR: '#1a7f37',
  FAIL: '#b42318',
  TIMEOUT: '#9a6700',
  ERROR: '#b42318',
  INFO: '#4b5563',
  SKIPPED: '#4b5563',
};

const ACCENT = '#00A886';
const INK = '#141414';

/** Escape a value for interpolation into HTML text or an attribute. */
export function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatDateTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  });
}

function formatDuration(ms) {
  if (ms === null || ms === undefined) return null;
  const n = Number(ms);
  if (!Number.isFinite(n)) return null;
  if (n < 1000) return `${n} ms`;
  return `${(n / 1000).toFixed(1)} s`;
}

/** "3 / 14 modules blocked" style value, or an em dash when unrecorded. */
function orDash(value) {
  return value === null || value === undefined || value === '' ? '—' : value;
}

function countSeverities(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) {
    const key = SEVERITY_COLOURS[f.severity] ? f.severity : 'INFO';
    counts[key] += 1;
  }
  return counts;
}

function renderCover(report) {
  const scope = report.scope || {};
  const agent = escapeHtml(orDash(report.agent));
  const profile = escapeHtml(orDash(scope.profile));
  const testTypes = Array.isArray(scope.test_types) && scope.test_types.length
    ? escapeHtml(scope.test_types.join(', '))
    : '—';
  const vendors = Array.isArray(scope.target_vendors) && scope.target_vendors.length
    ? escapeHtml(scope.target_vendors.join(', '))
    : 'Not detected during this assessment';

  const tested = Array.isArray(scope.modules_tested) && scope.modules_tested.length
    ? scope.modules_tested
    : [];

  return `
    <header class="cover">
      <div class="brand">
        <span class="brand-mark" aria-hidden="true">AI</span>
        <span class="brand-name">AgentIde</span>
      </div>
      <h1>EDR Assessment Report</h1>
      <p class="cover-sub">${agent} &middot; ${profile} profile &middot; ${testTypes} testing</p>

      <dl class="meta">
        <div><dt>Assessment ID</dt><dd>${escapeHtml(orDash(report.assessment_id))}</dd></div>
        <div><dt>Started</dt><dd>${escapeHtml(formatDateTime(scope.started_at))}</dd></div>
        <div><dt>Completed</dt><dd>${escapeHtml(formatDateTime(scope.completed_at))}</dd></div>
        <div><dt>Status</dt><dd>${escapeHtml(orDash(scope.status))}</dd></div>
        <div><dt>Target EDR</dt><dd>${vendors}</dd></div>
        <div><dt>Score</dt><dd>${scope.score === null || scope.score === undefined ? '—' : `${Math.round(scope.score)}%`}</dd></div>
      </dl>

      <div class="modules">
        <span class="modules-label">Modules executed (${tested.length})</span>
        <ul class="chips">
          ${
            tested.length
              ? tested.map((m) => `<li class="chip">${escapeHtml(m)}</li>`).join('')
              : '<li class="chip chip-muted">None recorded</li>'
          }
        </ul>
      </div>
    </header>`;
}

function renderSummary(report, counts) {
  const s = report.summary || {};
  const tiles = [
    { label: 'Modules run', value: s.totalModules ?? '—' },
    { label: 'Resisted', value: s.passedModules ?? '—' },
    { label: 'Gaps', value: s.failedModules ?? '—' },
    { label: 'Score', value: s.score === null || s.score === undefined ? '—' : `${Math.round(s.score)}%` },
  ];

  return `
    <section class="section">
      <h2>Summary</h2>
      <div class="tiles">
        ${tiles
          .map((t) => `<div class="tile"><span class="tile-value">${escapeHtml(t.value)}</span><span class="tile-label">${escapeHtml(t.label)}</span></div>`)
          .join('')}
      </div>
      <div class="severity-row">
        ${['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
          .map((k) => {
            const c = SEVERITY_COLOURS[k];
            return `<span class="sev" style="background:${c.bg};color:${c.fg}">${k}</span><span class="sev-count">${counts[k]}</span>`;
          })
          .join('')}
      </div>
    </section>`;
}

function renderFinding(f, i) {
  const sev = SEVERITY_COLOURS[f.severity] || SEVERITY_COLOURS.INFO;
  const resultColour = RESULT_COLOURS[f.result] || '#4b5563';
  const duration = formatDuration(f.duration_ms);
  const meta = [
    f.mitre ? `MITRE ${escapeHtml(f.mitre)}` : null,
    f.timestamp ? escapeHtml(formatDateTime(f.timestamp)) : null,
    duration ? escapeHtml(duration) : null,
  ].filter(Boolean).join(' &middot; ');

  return `
    <article class="finding${f.is_finding ? ' is-finding' : ''}">
      <div class="finding-head">
        <span class="finding-index">${i}</span>
        <h3>${escapeHtml(f.module)}</h3>
        <span class="sev" style="background:${sev.bg};color:${sev.fg}">${escapeHtml(f.severity)}</span>
        <span class="result" style="color:${resultColour}">${escapeHtml(f.result)}</span>
      </div>
      ${meta ? `<p class="finding-meta">${meta}</p>` : ''}
      <div class="block">
        <span class="block-label">Observation</span>
        <p>${escapeHtml(orDash(f.detail))}</p>
      </div>
      ${
        f.is_finding
          ? `<div class="block">
               <span class="block-label">Impact</span>
               <p>${escapeHtml(orDash(f.impact))}</p>
             </div>
             <div class="block">
               <span class="block-label">Recommendation</span>
               <p>${escapeHtml(orDash(f.recommendation))}</p>
             </div>`
          : ''
      }
    </article>`;
}

function renderDeploymentIntegrity(report) {
  const events = Array.isArray(report.deployment_integrity) ? report.deployment_integrity : [];
  if (events.length === 0) return '';
  return `
    <section class="section">
      <h2>Deployment integrity</h2>
      <p class="section-note">Activity observed while the assessment agent was running.</p>
      <ul class="integrity">
        ${events
          .map((e) => {
            const when = e.killed_at || e.timestamp || e.recovered_at;
            const what = e.module || e.event || e.result || 'Event';
            return `<li><span class="result" style="color:${RESULT_COLOURS[e.result] || '#1a7f37'}">${escapeHtml(orDash(e.result))}</span> ${escapeHtml(what)}${when ? ` — ${escapeHtml(formatDateTime(when))}` : ''}</li>`;
          })
          .join('')}
      </ul>
    </section>`;
}

const STYLES = `
  :root {
    --ink: ${INK};
    --muted: #6b7280;
    --rule: #e5e7eb;
    --accent: ${ACCENT};
    --surface: #f8fafc;
  }

  *, *::before, *::after { box-sizing: border-box; }

  html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }

  body {
    margin: 0;
    padding: 40px 44px 96px;
    background: #ffffff;
    color: var(--ink);
    font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 11pt;
    line-height: 1.6;
    /* The report is one continuous document; only the browser handles paging. */
    overflow: visible;
  }

  /* Running footer. position:fixed is repeated by browsers on every printed
     page, which is how a running head is achieved without @page margin boxes
     (a Paged.js extension no shipping browser implements). */
  .running-footer {
    position: fixed;
    left: 0; right: 0; bottom: 0;
    padding: 8px 44px;
    border-top: 1px solid var(--rule);
    color: var(--muted);
    font-size: 8pt;
    display: flex;
    justify-content: space-between;
    background: #ffffff;
  }

  .cover { border-bottom: 2px solid var(--ink); padding-bottom: 20px; margin-bottom: 28px; }

  .brand { display: flex; align-items: center; gap: 10px; margin-bottom: 18px; }
  .brand-mark {
    display: inline-flex; align-items: center; justify-content: center;
    width: 26px; height: 26px;
    background: var(--accent); color: var(--ink);
    font-weight: 700; font-size: 9pt;
  }
  .brand-name { font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; font-size: 10pt; }

  h1 { margin: 0 0 6px; font-size: 22pt; letter-spacing: -0.01em; }
  .cover-sub { margin: 0 0 20px; color: var(--muted); font-size: 10pt; }

  .meta { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px 24px; margin: 0 0 18px; }
  .meta dt { font-size: 8pt; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }
  .meta dd { margin: 2px 0 0; font-weight: 600; word-break: break-word; }

  .modules-label { font-size: 8pt; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }
  .chips { list-style: none; display: flex; flex-wrap: wrap; gap: 6px; padding: 0; margin: 8px 0 0; }
  .chip {
    border: 1px solid var(--rule); background: var(--surface);
    padding: 2px 8px; font-size: 9pt;
  }
  .chip-muted { color: var(--muted); }

  .section { margin-bottom: 30px; }
  h2 {
    margin: 0 0 12px; font-size: 12pt; letter-spacing: 0.06em; text-transform: uppercase;
    padding-bottom: 6px; border-bottom: 1px solid var(--ink);
  }
  .section-note { margin: -6px 0 12px; color: var(--muted); font-size: 9pt; }

  .tiles { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 16px; }
  .tile { border: 1px solid var(--rule); padding: 12px; background: var(--surface); }
  .tile-value { display: block; font-size: 20pt; font-weight: 700; line-height: 1.1; }
  .tile-label { display: block; font-size: 8pt; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); margin-top: 4px; }

  .severity-row { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
  .sev { display: inline-block; padding: 2px 8px; font-size: 8pt; font-weight: 700; letter-spacing: 0.06em; }
  .sev-count { margin-right: 14px; font-weight: 700; }

  .finding { border: 1px solid var(--rule); border-left: 3px solid var(--rule); padding: 14px 16px; margin-bottom: 12px; break-inside: avoid; page-break-inside: avoid; }
  .finding.is-finding { border-left-color: var(--ink); }

  .finding-head { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; margin-bottom: 4px; }
  .finding-index { font-weight: 700; color: var(--muted); }
  .finding-head h3 { margin: 0; font-size: 12pt; }
  .result { font-size: 9pt; font-weight: 700; letter-spacing: 0.06em; }
  .finding-meta { margin: 0 0 10px; color: var(--muted); font-size: 8.5pt; }

  .block { margin-top: 10px; }
  .block-label {
    display: inline-block; background: var(--ink); color: #ffffff;
    padding: 1px 7px; font-size: 7.5pt; font-weight: 700;
    letter-spacing: 0.08em; text-transform: uppercase;
  }
  .block p { margin: 5px 0 0; }

  .integrity { list-style: none; padding: 0; margin: 0; }
  .integrity li { padding: 5px 0; border-bottom: 1px solid var(--rule); font-size: 9.5pt; }

  .colophon { margin-top: 34px; padding-top: 14px; border-top: 1px solid var(--rule); color: var(--muted); font-size: 8.5pt; }
  .colophon p { margin: 0 0 4px; }

  /* ── Print ────────────────────────────────────────────────────────────────
     A4 with generous margins. Findings are kept whole rather than split across
     a page boundary, which is what break-inside buys. The fixed footer and its
     spacer are kept so the running head does not sit under body text. */
  @page { size: A4; margin: 16mm 14mm 18mm; }

  @media print {
    body { padding: 0; font-size: 9.5pt; }
    .tile, .chip { background: transparent; }
    .finding, .tile, .cover, .section { box-shadow: none; }
    .severity-row { break-inside: avoid; }
    h2 { break-after: avoid; }
  }
`;

/**
 * renderStandaloneHtml builds the complete, self-contained HTML document for a
 * report payload.
 */
export function renderStandaloneHtml(report, { generatedAt = new Date().toISOString() } = {}) {
  const findings = Array.isArray(report.module_results) ? report.module_results : [];
  const counts = countSeverities(findings);
  const agent = orDash(report.agent);

  const findingBlocks = findings.length
    ? findings.map((f, i) => renderFinding(f, i + 1)).join('')
    : '<p class="section-note">No module results were recorded for this assessment.</p>';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentIde Assessment Report — ${escapeHtml(agent)}</title>
<!-- Generated ${escapeHtml(generatedAt)}. Self-contained: open directly in a
     browser or print to PDF. No scripts, no external stylesheet. -->
<style>${STYLES}</style>
</head>
<body>
${renderCover(report)}
${renderSummary(report, counts)}
<section class="section">
  <h2>Findings</h2>
  ${findingBlocks}
</section>
${renderDeploymentIntegrity(report)}
<div class="colophon">
  <p>Generated by AgentIde ${escapeHtml(generatedAt.slice(0, 10))}.</p>
  <p>Severity is derived from each module's recorded outcome: a failure means the endpoint
     did not resist the technique, a pass means it did, and an inconclusive outcome is
     reported as neither. Impact and recommendation text is fixed per module.</p>
  <p>Scope values are reported as recorded. A field marked &ldquo;&mdash;&rdquo; was not
     captured during this assessment.</p>
</div>
<div class="running-footer">
  <span>AgentIde &middot; ${escapeHtml(agent)}</span>
  <span>${escapeHtml(report.assessment_id || '')}</span>
</div>
</body>
</html>`;
}