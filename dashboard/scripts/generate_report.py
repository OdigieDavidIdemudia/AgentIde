#!/usr/bin/env python3
"""
Generate Markdown/Docx reports from AgentIDE assessment JSON export.

Usage:
  python generate_report.py input.json --output report.md
  python generate_report.py input.json --output report.docx
"""

import json
import sys
import argparse
from datetime import datetime
from pathlib import Path

try:
    from docx import Document
    from docx.shared import Inches, Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False

# Severity colors for markdown
SEVERITY_COLORS = {
    "PASS": "🟢",
    "FAIL": "🔴",
    "BLOCKED": "🟢",
    "BLOCKED_BY_EDR": "🟢",
    "AGENT_RECOVERED": "🟢",
    "TIMEOUT": "🟡",
    "SKIPPED": "⚪",
    "INFO": "🔵",
    "ERROR": "🔴",
}

MITRE_COLORS = {
    "T1059": "Execution",
    "T1059.001": "Command and Scripting Interpreter",
    "T1071.001": "Application Layer Protocol",
    "T1110.003": "Password Spraying",
    "T1562.001": "Disable Security Tools",
    "T1562": "Impair Defenses",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1547": "Boot or Logon Autostart Execution",
}

def format_duration(ms):
    if ms is None:
        return "N/A"
    if ms < 1000:
        return f"{ms}ms"
    return f"{ms/1000:.1f}s"

def format_timestamp(ts):
    try:
        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except:
        return ts

def get_severity_badge(result):
    return SEVERITY_COLORS.get(result, "⚪")

def generate_markdown(data):
    """Generate markdown report from assessment JSON."""
    lines = []
    
    # Header
    lines.append(f"# AgentIDE Security Assessment Report")
    lines.append(f"")
    lines.append(f"**Agent:** {data.get('agent', 'Unknown')}")
    lines.append(f"**Exported:** {format_timestamp(data.get('exported_at', ''))}")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")
    
    # Executive Summary
    summary = data.get('summary', {})
    lines.append(f"## Executive Summary")
    lines.append(f"")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total Modules | {summary.get('totalModules', 0)} |")
    lines.append(f"| Passed | {summary.get('passedModules', 0)} {get_severity_badge('PASS')} |")
    lines.append(f"| Failed | {summary.get('failedModules', 0)} {get_severity_badge('FAIL')} |")
    lines.append(f"| Kill/Recovery Events | {summary.get('totalTampers', 0)} |")
    lines.append(f"")
    
    # Deployment Integrity
    deployment = data.get('deployment_integrity', [])
    if deployment:
        lines.append(f"## Deployment Integrity (Blackbox)")
        lines.append(f"")
        for item in deployment:
            result = item.get('result', 'UNKNOWN')
            badge = get_severity_badge(result)
            lines.append(f"### {badge} {item.get('event', 'Unknown Event')}")
            lines.append(f"")
            lines.append(f"- **Description:** {item.get('description', 'N/A')}")
            lines.append(f"- **Downtime:** {item.get('downtime_str', 'N/A')}")
            lines.append(f"- **Killed:** {format_timestamp(item.get('killed_at', ''))}")
            lines.append(f"- **Recovered:** {format_timestamp(item.get('recovered_at', ''))}")
            lines.append(f"- **Recovery #:** {item.get('recovery_num', 'N/A')}")
            lines.append(f"- **Total Kills:** {item.get('total_kills', 'N/A')}")
            lines.append(f"")
    
    # Module Results
    modules = data.get('module_results', [])
    if modules:
        lines.append(f"## Module Results")
        lines.append(f"")
        lines.append(f"| Module | Result | Duration | MITRE | Test Type |")
        lines.append(f"|--------|--------|----------|-------|-----------|")
        for m in modules:
            result = m.get('result', 'UNKNOWN')
            badge = get_severity_badge(result)
            mitre = m.get('mitre', 'N/A')
            mitre_name = MITRE_COLORS.get(mitre, '')
            mitre_display = f"{mitre} ({mitre_name})" if mitre_name else mitre
            lines.append(f"| {m.get('module', 'N/A')} | {badge} {result} | {format_duration(m.get('duration_ms'))} | {mitre_display} | {m.get('test_type', 'N/A')} |")
        lines.append(f"")
    
    # Detailed Findings
    lines.append(f"## Detailed Findings")
    lines.append(f"")
    for m in modules:
        result = m.get('result', 'UNKNOWN')
        badge = get_severity_badge(result)
        lines.append(f"### {badge} {m.get('module', 'N/A')} — {result}")
        lines.append(f"")
        lines.append(f"**Detail:** {m.get('detail', 'N/A')}")
        lines.append(f"")
        lines.append(f"- **MITRE:** {m.get('mitre', 'N/A')} ({MITRE_COLORS.get(m.get('mitre', ''), 'N/A')})")
        lines.append(f"- **Test Type:** {m.get('test_type', 'N/A')}")
        lines.append(f"- **Duration:** {format_duration(m.get('duration_ms'))}")
        lines.append(f"- **Timestamp:** {format_timestamp(m.get('timestamp', ''))}")
        if m.get('session_id'):
            lines.append(f"- **Session ID:** {m.get('session_id')}")
        lines.append(f"")
    
    # Session Findings
    findings = data.get('session_findings', [])
    if findings:
        lines.append(f"## Session Findings")
        lines.append(f"")
        for f in findings:
            result = f.get('result', 'UNKNOWN')
            badge = get_severity_badge(result)
            lines.append(f"### {badge} {f.get('title', 'N/A')} — {result}")
            lines.append(f"")
            lines.append(f"**Phase:** {f.get('phase', 'N/A')} | **Category:** {f.get('category', 'N/A')}")
            lines.append(f"")
            lines.append(f"**Detail:** {f.get('detail', 'N/A')}")
            lines.append(f"")
            lines.append(f"- **MITRE:** {f.get('mitre', 'N/A')}")
            lines.append(f"- **Timestamp:** {format_timestamp(f.get('timestamp', ''))}")
            lines.append(f"")
    
    # Footer
    lines.append(f"---")
    lines.append(f"")
    lines.append(f"*Report generated by AgentIDE EDR/XDR Assessment Framework*")
    lines.append(f"*{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
    
    return "\n".join(lines)

def generate_docx(data, output_path):
    """Generate DOCX report from assessment JSON."""
    if not DOCX_AVAILABLE:
        raise RuntimeError("python-docx not installed. Run: pip install python-docx")
    
    doc = Document()
    
    # Title
    title = doc.add_heading('AgentIDE Security Assessment Report', 0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    
    # Meta info
    meta = doc.add_paragraph()
    meta.add_run(f"Agent: ").bold = True
    meta.add_run(f"{data.get('agent', 'Unknown')}")
    meta.add_run(f"\nExported: ").bold = True
    meta.add_run(f"{format_timestamp(data.get('exported_at', ''))}")
    meta.add_run(f"\nGenerated: ").bold = True
    meta.add_run(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    doc.add_paragraph("─" * 50)
    
    # Executive Summary
    doc.add_heading('Executive Summary', level=1)
    summary = data.get('summary', {})
    table = doc.add_table(rows=5, cols=2, style='Table Grid')
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    headers = ["Metric", "Value"]
    for i, h in enumerate(headers):
        table.rows[0].cells[i].text = h
        for p in table.rows[0].cells[i].paragraphs:
            for run in p.runs:
                run.bold = True
    
    rows_data = [
        ("Total Modules", str(summary.get('totalModules', 0))),
        ("Passed", f"{summary.get('passedModules', 0)} ✅"),
        ("Failed", f"{summary.get('failedModules', 0)} ❌"),
        ("Kill/Recovery Events", str(summary.get('totalTampers', 0))),
    ]
    for i, (metric, value) in enumerate(rows_data, 1):
        table.rows[i].cells[0].text = metric
        table.rows[i].cells[1].text = value
    
    doc.add_paragraph("")
    
    # Deployment Integrity
    deployment = data.get('deployment_integrity', [])
    if deployment:
        doc.add_heading('Deployment Integrity (Blackbox)', level=1)
        for item in deployment:
            result = item.get('result', 'UNKNOWN')
            p = doc.add_paragraph()
            p.add_run(f"{item.get('event', 'Unknown Event')} — {result}").bold = True
            details = [
                ("Description", item.get('description', 'N/A')),
                ("Downtime", item.get('downtime_str', 'N/A')),
                ("Killed", format_timestamp(item.get('killed_at', ''))),
                ("Recovered", format_timestamp(item.get('recovered_at', ''))),
                ("Recovery #", str(item.get('recovery_num', 'N/A'))),
                ("Total Kills", str(item.get('total_kills', 'N/A'))),
            ]
            for label, value in details:
                p = doc.add_paragraph(style='List Bullet')
                p.add_run(f"{label}: ").bold = True
                p.add_run(str(value))
    
    # Module Results
    modules = data.get('module_results', [])
    if modules:
        doc.add_heading('Module Results', level=1)
        table = doc.add_table(rows=1, cols=5, style='Table Grid')
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        headers = ["Module", "Result", "Duration", "MITRE", "Test Type"]
        for i, h in enumerate(headers):
            table.rows[0].cells[i].text = h
            for p in table.rows[0].cells[i].paragraphs:
                for run in p.runs:
                    run.bold = True
        
        for m in modules:
            row = table.add_row()
            row.cells[0].text = m.get('module', 'N/A')
            row.cells[1].text = m.get('result', 'UNKNOWN')
            row.cells[2].text = format_duration(m.get('duration_ms'))
            row.cells[3].text = m.get('mitre', 'N/A')
            row.cells[4].text = m.get('test_type', 'N/A')
    
    doc.add_paragraph("")
    
    # Detailed Findings
    doc.add_heading('Detailed Findings', level=1)
    for m in modules:
        result = m.get('result', 'UNKNOWN')
        heading = doc.add_heading(f"{m.get('module', 'N/A')} — {result}", level=2)
        doc.add_paragraph(m.get('detail', 'N/A'))
        
        details = [
            ("MITRE", f"{m.get('mitre', 'N/A')} ({MITRE_COLORS.get(m.get('mitre', ''), 'N/A')})"),
            ("Test Type", m.get('test_type', 'N/A')),
            ("Duration", format_duration(m.get('duration_ms'))),
            ("Timestamp", format_timestamp(m.get('timestamp', ''))),
        ]
        if m.get('session_id'):
            details.append(("Session ID", m.get('session_id')))
        
        for label, value in details:
            p = doc.add_paragraph(style='List Bullet')
            p.add_run(f"{label}: ").bold = True
            p.add_run(str(value))
    
    # Session Findings
    findings = data.get('session_findings', [])
    if findings:
        doc.add_heading('Session Findings', level=1)
        for f in findings:
            result = f.get('result', 'UNKNOWN')
            doc.add_heading(f"{f.get('title', 'N/A')} — {result}", level=2)
            p = doc.add_paragraph()
            p.add_run(f"Phase: ").bold = True
            p.add_run(f"{f.get('phase', 'N/A')} | Category: {f.get('category', 'N/A')}")
            doc.add_paragraph(f.get('detail', 'N/A'))
            
            details = [
                ("MITRE", f.get('mitre', 'N/A')),
                ("Timestamp", format_timestamp(f.get('timestamp', ''))),
            ]
            for label, value in details:
                p = doc.add_paragraph(style='List Bullet')
                p.add_run(f"{label}: ").bold = True
                p.add_run(str(value))
    
    # Footer
    doc.add_paragraph("")
    footer = doc.add_paragraph()
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = footer.add_run(f"Report generated by AgentIDE EDR/XDR Assessment Framework\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    run.italic = True
    run.font.size = Pt(9)
    run.font.color.rgb = RGBColor(0x80, 0x80, 0x80)
    
    doc.save(output_path)

def main():
    parser = argparse.ArgumentParser(description="Generate Markdown/Docx report from AgentIDE assessment JSON")
    parser.add_argument("input", help="Input JSON file")
    parser.add_argument("-o", "--output", help="Output file (default: input.md or input.docx)")
    parser.add_argument("--format", choices=["md", "docx"], default="md", help="Output format")
    args = parser.parse_args()
    
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: Input file not found: {input_path}")
        sys.exit(1)
    
    with open(input_path, 'r') as f:
        data = json.load(f)
    
    if args.output:
        output_path = Path(args.output)
    else:
        suffix = ".docx" if args.format == "docx" else ".md"
        output_path = input_path.with_suffix(suffix)
    
    if args.format == "docx":
        if not DOCX_AVAILABLE:
            print("ERROR: python-docx not installed. Run: pip install python-docx")
            sys.exit(1)
        generate_docx(data, output_path)
    else:
        markdown = generate_markdown(data)
        output_path.write_text(markdown, encoding='utf-8')
    
    print(f"[OK] Report generated: {output_path}")

if __name__ == "__main__":
    main()