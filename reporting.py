import csv
import io
import json
from datetime import datetime

from rich.table import Table
from rich.panel import Panel
from rich import box

_SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
_SEVERITY_COLORS = {
    "Critical": "bold red1",
    "High": "bold red",
    "Medium": "bold yellow",
    "Low": "bold blue",
}
_SEVERITY_HTML_COLORS = {
    "Critical": "#b71c1c",
    "High": "#ffcdd2",
    "Medium": "#ffecb3",
    "Low": "#cce5ff",
}
_REMEDIATION = {
    "Critical": "Fix immediately. Rotate any exposed credentials and audit all access logs.",
    "High": "Fix as soon as possible. Validate all user input server-side and use parameterised queries or ORMs.",
    "Medium": "Schedule a fix. Implement the missing security configuration on your web server or application.",
    "Low": "Address in your next maintenance window. Review application logic and configurations.",
}


def _sorted_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "Low"), 1),
        reverse=True,
    )
def print_terminal_report(findings: list[dict], target_url: str, console) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if not findings:
        console.print(Panel(
            "[bold green]No vulnerabilities detected.[/bold green]\n"
            "This does not guarantee the target is secure — manual review is always recommended.",
            title=f"Scan Complete — {target_url}",
            border_style="green",
        ))
        return
    table = Table(
        title=f"Vulnerability Report  •  {target_url}  •  {timestamp}",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold white on dark_blue",
    )
    table.add_column("Severity", style="bold", width=10, justify="center")
    table.add_column("CVSS", width=6, justify="center")
    table.add_column("Type", style="cyan", width=28)
    table.add_column("URL", style="dim", width=40, overflow="fold")
    table.add_column("Details", width=45, overflow="fold")
    for f in _sorted_findings(findings):
        sev = f.get("severity", "Low")
        color = _SEVERITY_COLORS.get(sev, "white")
        cvss = f.get("cvss")
        cvss_str = f"[bold]{cvss}[/bold]" if cvss else "—"
        table.add_row(
            f"[{color}]{sev}[/{color}]",
            cvss_str,
            f.get("type", "Unknown"),
            f.get("url", ""),
            f.get("details", ""),
        )
    console.print(table)
    console.print(
        f"\n[bold]Summary:[/bold] [red]{sum(1 for f in findings if f.get('severity') in ('Critical','High'))} High/Critical[/red]"
        f"  [yellow]{sum(1 for f in findings if f.get('severity') == 'Medium')} Medium[/yellow]"
        f"  [blue]{sum(1 for f in findings if f.get('severity') == 'Low')} Low[/blue]"
        f"  ({len(findings)} total)"
    )
def generate_json_report(findings: list[dict], target_url: str) -> str:
    report = {
        "meta": {
            "target": target_url,
            "generated_at": datetime.now().isoformat(),
            "total_findings": len(findings),
        },
        "findings": _sorted_findings(findings),
    }
    return json.dumps(report, indent=2)
def generate_csv_report(findings: list[dict], target_url: str) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=["severity", "type", "url", "details"],
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(_sorted_findings(findings))
    return buf.getvalue()
def generate_html_report(findings: list[dict], target_url: str) -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cards = ""
    if not findings:
        cards = "<p>No vulnerabilities found. Great job!</p>"
    else:
        for f in _sorted_findings(findings):
            sev = f.get("severity", "Low")
            bg = _SEVERITY_HTML_COLORS.get(sev, "#cce5ff")
            remediation = _REMEDIATION.get(sev, "")
            details_html = f.get("details", "").replace("\n", "<br>")
            cards += f"""
            <div class="card" style="border-left:5px solid {bg};">
              <div class="card-header">
                <span class="badge" style="background:{bg};">{sev}</span>
                <span class="card-title">{f.get("type","")}</span>
              </div>
              <div class="card-body">
                <p><strong>URL:</strong> <a href="{f.get('url','')}" target="_blank">{f.get('url','')}</a></p>
                <p><strong>Details:</strong> {details_html}</p>
                <p><strong>Remediation:</strong> {remediation}</p>
              </div>
            </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Vulnerability Report — {target_url}</title>
  <style>
    body{{font-family:'Segoe UI',sans-serif;margin:0;padding:0;background:#f4f7f6;}}
    .container{{width:80%;margin:2em auto;}}
    .report-header{{background:#2c3e50;color:#fff;padding:2em;border-radius:8px;text-align:center;}}
    .report-header h1{{margin:0;}}
    .report-header p{{margin:4px 0;opacity:.8;}}
    .card{{background:#fff;border-radius:8px;margin-bottom:1.5em;box-shadow:0 2px 4px rgba(0,0,0,.1);}}
    .card-header{{padding:1em;border-bottom:1px solid #eee;display:flex;align-items:center;gap:1em;}}
    .badge{{padding:.3em .8em;border-radius:15px;font-weight:700;}}
    .card-title{{font-size:1.2em;font-weight:700;color:#34495e;}}
    .card-body{{padding:1em;}}
    .card-body p{{margin:.5em 0;line-height:1.6;}}
    a{{color:#3498db;text-decoration:none;}}
    a:hover{{text-decoration:underline;}}
  </style>
</head>
<body>
  <div class="container">
    <div class="report-header">
      <h1>Vulnerability Scan Report</h1>
      <p><strong>Target:</strong> {target_url}</p>
      <p><strong>Generated:</strong> {timestamp}</p>
      <p><strong>Findings:</strong> {len(findings)}</p>
    </div>
    <h2 style="margin-top:2em;">Findings ({len(findings)} total)</h2>
    {cards}
  </div>
</body>
</html>"""
