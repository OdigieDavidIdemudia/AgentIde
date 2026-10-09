package reporter

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// WriteHTML generates a self-contained HTML report using the minimalism style variant.
func (r *Report) WriteHTML(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("cannot create HTML file: %w", err)
	}
	defer f.Close()

	_, err = fmt.Fprint(f, r.buildHTML())
	return err
}

func (r *Report) buildHTML() string {
	rows := ""
	for _, res := range r.Results {
		statusClass := "pass"
		statusLabel := "PASS"
		if !res.Passed {
			statusClass = "fail"
			statusLabel = "FAIL"
		}
		if strings.HasPrefix(res.Detail, "SKIPPED") || strings.HasPrefix(res.Detail, "INFO") {
			statusClass = "info"
			statusLabel = strings.Split(res.Detail, " ")[0]
		}

		rows += fmt.Sprintf(`
		<tr>
			<td><code>%s</code></td>
			<td>%s</td>
			<td>%s</td>
			<td class="latency">%s</td>
			<td>%s</td>
			<td><span class="badge %s">%s</span></td>
		</tr>`, res.ModuleName, esc(res.Action), esc(res.Detail), formatLatency(res.ElapsedMs), formatArtifacts(res.Artifacts), statusClass, statusLabel)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AgentIde Report — %s</title>
<style>
  /* Design standard: technicalMono pairing, minimalism variant, dark mode */
  @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;600&family=JetBrains+Mono:wght@400;500&display=swap');

  :root {
    --bg:        #141414;
    --surface:   #242424;
    --border:    #3A3A3A;
    --text:      #FAFAFA;
    --text-sec:  #7A7A7A;
    --text-ter:  #565656;
    --accent:    #00D4AA;
    --pass:      #00D4AA;
    --fail:      #E05252;
    --info:      #A8A8A8;
    --shadow:    0px 1px 3px rgba(0,0,0,0.24);
    --xxs: 4px; --xs: 8px; --sm: 12px; --md: 16px;
    --lg: 24px; --xl: 32px; --2xl: 48px; --3xl: 64px;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    font-weight: 400;
    font-size: 14.4px;
    line-height: 1.7;
    max-width: 1200px;
    margin: 0 auto;
    padding: var(--3xl) var(--xl);
  }

  h1, h2, h3, .label {
    font-family: 'Space Grotesk', sans-serif;
    font-weight: 300;
    letter-spacing: -0.5px;
  }

  /* ── Header ─────────────────────────────────────────── */
  .header {
    padding-bottom: var(--xl);
    margin-bottom: var(--xl);
    border-bottom: 1px solid var(--border);
  }
  .header h1 {
    font-size: 31px;
    font-weight: 300;
    color: var(--text);
    margin-bottom: var(--xs);
  }
  .header .meta {
    color: var(--text-sec);
    font-size: 12.8px;
    line-height: 1.5;
  }
  .header .meta span { margin-right: var(--lg); }

  /* ── Score strip ─────────────────────────────────────── */
  .scorestrip {
    display: grid;
    grid-template-columns: 2fr 1fr 1fr 1fr;
    gap: 1px;
    background: var(--border);
    border: 1px solid var(--border);
    border-radius: 4px;
    overflow: hidden;
    margin-bottom: var(--2xl);
    box-shadow: var(--shadow);
  }
  .scorestrip-cell {
    background: var(--surface);
    padding: var(--lg) var(--xl);
  }
  .scorestrip-cell .label {
    font-size: 11px;
    font-weight: 400;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--text-sec);
    margin-bottom: var(--xs);
  }
  .scorestrip-cell .value {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 39px;
    font-weight: 300;
    line-height: 1;
    color: var(--text);
  }
  .scorestrip-cell.primary .value { color: var(--accent); }
  .scorestrip-cell.pass-c  .value { color: var(--pass); }
  .scorestrip-cell.fail-c  .value { color: var(--fail); }

  /* ── Table ───────────────────────────────────────────── */
  .table-wrap {
    border: 1px solid var(--border);
    border-radius: 4px;
    overflow: hidden;
    box-shadow: var(--shadow);
  }
  table {
    width: 100%%;
    border-collapse: collapse;
  }
  thead { background: var(--surface); }
  th {
    padding: var(--sm) var(--lg);
    text-align: left;
    font-family: 'Space Grotesk', sans-serif;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-sec);
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    background: var(--surface);
  }
  td {
    padding: var(--sm) var(--lg);
    font-size: 12.8px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
    color: var(--text);
  }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: var(--surface); transition: background 150ms cubic-bezier(0.4,0,0.2,1); }
  td.latency { color: var(--text-sec); font-size: 12.8px; }
  code {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12.8px;
    color: var(--text-sec);
  }

  /* ── Badges ──────────────────────────────────────────── */
  .badge {
    display: inline-block;
    padding: 2px var(--xs);
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    font-weight: 500;
    letter-spacing: 1px;
    text-transform: uppercase;
    border-radius: 2px;
    border: 1px solid;
  }
  .badge.pass { color: var(--pass);  border-color: var(--pass);  background: rgba(0,212,170,0.06); }
  .badge.fail { color: var(--fail);  border-color: var(--fail);  background: rgba(224,82,82,0.06); }
  .badge.info { color: var(--info);  border-color: var(--border); background: transparent; }

  /* ── Footer ──────────────────────────────────────────── */
  .footer {
    margin-top: var(--xl);
    padding-top: var(--md);
    border-top: 1px solid var(--border);
    color: var(--text-ter);
    font-size: 12.8px;
    display: flex;
    justify-content: space-between;
  }
</style>
</head>
<body>

<div class="header">
  <h1>Assessment Report</h1>
  <div class="meta">
    <span>Vendor: <strong style="color:var(--text)">%s</strong></span>
    <span>Generated: %s</span>
    <span>Duration: %s</span>
  </div>
</div>

<div class="scorestrip">
  <div class="scorestrip-cell primary">
    <div class="label">Detection Score</div>
    <div class="value">%.0f%%</div>
  </div>
  <div class="scorestrip-cell pass-c">
    <div class="label">Passed</div>
    <div class="value">%d</div>
  </div>
  <div class="scorestrip-cell fail-c">
    <div class="label">Failed</div>
    <div class="value">%d</div>
  </div>
  <div class="scorestrip-cell">
    <div class="label">Skipped</div>
    <div class="value">%d</div>
  </div>
</div>

<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Module</th>
        <th>Test Action</th>
        <th>Outcome</th>
        <th>Latency</th>
        <th>Files Created</th>
        <th>Result</th>
      </tr>
    </thead>
    <tbody>%s</tbody>
  </table>
</div>

<div class="footer">
  <span>AgentIde v0.3.0 &mdash; Vendor-agnostic EDR/XDR POC Assessment Framework</span>
  <span>%s</span>
</div>

</body>
</html>`,
		r.VendorName,
		// body interpolations:
		r.VendorName,
		r.GeneratedAt.Format("02 Jan 2006, 15:04 UTC"),
		r.TotalTime.Round(time.Second),
		r.Score(),
		r.Passed,
		r.Failed,
		r.Skipped,
		rows,
		r.GeneratedAt.Format(time.RFC3339),
	)
}

func esc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func formatLatency(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	sec := float64(ms) / 1000
	if sec < 60 {
		return fmt.Sprintf("%.1fs", sec)
	}
	min := int(sec) / 60
	remSec := int(sec) % 60
	return fmt.Sprintf("%dm %ds", min, remSec)
}

// formatArtifacts renders the list of files a module created, one per line.
func formatArtifacts(paths []string) string {
	if len(paths) == 0 {
		return "<span style=\"color:var(--text-ter)\">&mdash;</span>"
	}
	parts := make([]string, 0, len(paths))
	for _, p := range paths {
		parts = append(parts, "<code>"+esc(p)+"</code>")
	}
	return strings.Join(parts, "<br>")
}
