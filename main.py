
"""vscan — terminal vulnerability scanner."""

import logging
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.rule import Rule
from rich.table import Table

from scanner import run_scan, PROFILES
from reporting import (
    generate_csv_report,
    generate_html_report,
    generate_json_report,
    print_terminal_report,
)

console = Console()

_BANNER = """
██╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██║   ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
██║   ██║███████╗██║     ███████║██╔██╗ ██║
╚██╗ ██╔╝╚════██║██║     ██╔══██║██║╚██╗██║
 ╚████╔╝ ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═══╝  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
         Web Vulnerability Scanner  v2.0
"""

_SCANNER_CHOICES = frozenset(
    {"xss", "sqli", "headers", "files", "paths", "cookies", "bac", "cors", "ssl", "login_bypass"}
)

_SCANNER_META = [
    ("xss",     "Reflected XSS in HTML forms",       "CWE-79"),
    ("sqli",    "Error-based SQL injection",          "CWE-89"),
    ("headers", "Missing security headers",           "CWE-693"),
    ("files",   "Sensitive file exposure",            "CWE-200"),
    ("paths",   "Path/directory exposure",            "CWE-200"),
    ("cookies", "Insecure cookie flags",              "CWE-614"),
    ("bac",     "Broken access control",              "CWE-284"),
    ("cors",    "CORS misconfiguration",              "CWE-942"),
    ("ssl",     "SSL/TLS configuration issues",       "CWE-295"),
    ("login_bypass", "Login bypass",                   "CWE-918"),
]


def _is_valid_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def _validate_url(_ctx, _param, value: str) -> str:
    if value and not _is_valid_url(value):
        raise click.BadParameter("URL must start with http:// or https://")
    return value


def _print_main_menu() -> None:
    table = Table(box=box.ROUNDED, border_style="cyan", show_header=False, padding=(0, 2))
    table.add_column("opt",  style="bold cyan",  width=4)
    table.add_column("name", style="bold white",  width=16)
    table.add_column("desc", style="dim")

    table.add_row("[1]", "Quick Scan",   "headers, paths, cookies, ssl  (fastest)")
    table.add_row("[2]", "Full Scan",    "all 9 scanners                (default)")
    table.add_row("[3]", "Stealth Scan", "all 9 scanners + slow delays  (evasive)")
    table.add_row("[4]", "Custom Scan",  "choose individual scanners")
    table.add_row("",    "",             "")
    table.add_row("[Q]", "Quit",         "")

    console.print()
    console.print(table)
    console.print()


def _custom_scanner_menu() -> set[str] | None:
    """Show numbered scanner list; return selected set or None if cancelled."""
    table = Table(
        title="Available Scanners",
        box=box.SIMPLE_HEAVY,
        border_style="cyan",
        header_style="bold white on dark_blue",
        padding=(0, 1),
    )
    table.add_column("#",         justify="right", width=3)
    table.add_column("Scanner",   style="cyan",    width=10)
    table.add_column("Checks",                     width=36)
    table.add_column("Reference", style="dim",     width=9)

    for i, (key, desc, ref) in enumerate(_SCANNER_META, 1):
        table.add_row(str(i), key, desc, ref)

    console.print()
    console.print(table)
    console.print()

    raw = Prompt.ask(
        "  [bold cyan]Select scanners[/bold cyan]  "
        "[dim](comma-separated numbers e.g. 1,3,5  —  or 'all' / 'back')[/dim]",
        default="all",
    )

    stripped = raw.strip().lower()
    if stripped in ("back", "b", "q", ""):
        return None
    if stripped == "all":
        return set(_SCANNER_CHOICES)

    selected: set[str] = set()
    for token in stripped.split(","):
        token = token.strip()
        if token.isdigit():
            idx = int(token) - 1
            if 0 <= idx < len(_SCANNER_META):
                selected.add(_SCANNER_META[idx][0])
            else:
                console.print(f"  [yellow]  {token} is out of range, skipped.[/yellow]")
        elif token:
            console.print(f"  [yellow]  '{token}' is not a number, skipped.[/yellow]")

    if not selected:
        console.print("  [red]No valid scanners selected — returning to menu.[/red]")
        return None

    console.print(f"\n  [green]Selected:[/green] {', '.join(sorted(selected))}\n")
    return selected


def _prompt_target() -> str | None:
    """Prompt for target URL; returns None if the user goes back."""
    console.print()
    raw = Prompt.ask("  [bold cyan]Target URL[/bold cyan]  [dim](or 'back')[/dim]")
    stripped = raw.strip().lower()
    if stripped in ("back", "b", "q", "exit", "quit", ""):
        return None
    if not _is_valid_url(raw.strip()):
        console.print("  [red]✗ Invalid URL — must start with http:// or https://[/red]")
        return None
    return raw.strip()


def _prompt_format() -> str:
    console.print()
    return Prompt.ask(
        "  [bold cyan]Output format[/bold cyan]  "
        "[dim](table = terminal only, others are also saved to file)[/dim]",
        choices=["table", "json", "csv", "html"],
        default="table",
    )


def _execute_scan(target, profile=None, fmt="table", output=None,
                  crawl=False, timeout=5, threads=5, custom_scanners=None):
    if profile:
        p = PROFILES[profile]
        enabled = set(p["scanners"])
        intensity = p["intensity"]
        threads = p["threads"]
    elif custom_scanners:
        enabled = custom_scanners
        intensity = "fast"
    else:
        enabled = set(_SCANNER_CHOICES)
        intensity = "fast"

    console.print(Panel(
        f"[bold]Target:[/bold]    {target}\n"
        f"[bold]Profile:[/bold]   {profile or 'custom'}\n"
        f"[bold]Scanners:[/bold]  {', '.join(sorted(enabled))}\n"
        f"[bold]Intensity:[/bold] {intensity}   "
        f"[bold]Threads:[/bold] {threads}   "
        f"[bold]Crawl:[/bold] {'yes' if crawl else 'no'}",
        title="Scan Configuration",
        border_style="blue",
    ))

    scan_config = {
        "scan_intensity": intensity,
        "run_xss_scan":    "xss"     in enabled,
        "run_sqli_scan":   "sqli"    in enabled,
        "run_file_scan":   "files"   in enabled,
        "run_header_scan": "headers" in enabled,
        "run_path_scan":   "paths"   in enabled,
        "run_cookie_scan": "cookies" in enabled,
        "run_bac_scan":    "bac"     in enabled,
        "run_cors_scan":   "cors"    in enabled,
        "run_ssl_scan":    "ssl"     in enabled,
        "run_login_bypass_scan": "login_bypass"     in enabled,
        "crawl": crawl,
        "timeout": timeout,
        "threads": threads,
    }

    try:
        findings = run_scan(target, scan_config, console)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/yellow]")
        return []

    print_terminal_report(findings, target, console)

    save_path = output
    if fmt != "table" and not save_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        save_path = f"report_{ts}.{fmt}"

    if save_path:
        path = Path(save_path)
        if fmt == "json":
            path.write_text(generate_json_report(findings, target), encoding="utf-8")
        elif fmt == "csv":
            path.write_text(generate_csv_report(findings, target), encoding="utf-8")
        elif fmt == "html":
            path.write_text(generate_html_report(findings, target), encoding="utf-8")
        else:
            path = path.with_suffix(".json")
            path.write_text(generate_json_report(findings, target), encoding="utf-8")
        console.print(f"\n[green]  Report saved → {path}[/green]")

    return findings


def _interactive() -> None:
    console.print(_BANNER, style="bold cyan")
    console.print(
        "  [dim]Scan a web target for common vulnerabilities.[/dim]\n"
        "  [dim]Enter a number to select an option. Type [bold]back[/bold] "
        "or [bold]Q[/bold] at any prompt to return.[/dim]\n"
    )

    while True:
        console.print(Rule(style="cyan"))
        _print_main_menu()

        choice = Prompt.ask("  [bold cyan]Choice[/bold cyan]", default="2").strip().lower()

        if choice == "q":
            console.print("\n  [bold cyan]Goodbye![/bold cyan]\n")
            break

        if choice in ("1", "2", "3"):
            profile_map = {"1": "quick", "2": "full", "3": "stealth"}
            profile = profile_map[choice]
            target = _prompt_target()
            if target is None:
                continue
            fmt = _prompt_format()
            console.print()
            _execute_scan(target=target, profile=profile, fmt=fmt, output=None)

        elif choice == "4":
            custom = _custom_scanner_menu()
            if custom is None:
                continue
            target = _prompt_target()
            if target is None:
                continue
            fmt = _prompt_format()
            console.print()
            _execute_scan(target=target, custom_scanners=custom, fmt=fmt, output=None)

        else:
            console.print("  [red]Invalid choice — enter 1, 2, 3, 4, or Q.[/red]")
            continue

        console.print()
        if not Confirm.ask("  [bold cyan]Run another scan?[/bold cyan]", default=True):
            console.print("\n  [bold cyan]Goodbye![/bold cyan]\n")
            break


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option("2.0.0", "-V", "--version", prog_name="vscan")
@click.argument("target", required=False, callback=_validate_url, is_eager=True, expose_value=True)
@click.option("--profile", default=None,
              type=click.Choice(["quick", "full", "stealth"], case_sensitive=False))
@click.option("--output", "-o", type=click.Path())
@click.option("--format", "fmt", default="table", show_default=True,
              type=click.Choice(["table", "json", "csv", "html"], case_sensitive=False))
@click.option("--crawl", is_flag=True)
@click.option("--timeout", default=5, show_default=True, type=int)
@click.option("--threads", default=5, show_default=True, type=int)
@click.option("--verbose", "-v", is_flag=True)
def scan(target, profile, output, fmt, crawl, timeout, threads, verbose):
    """Web vulnerability scanner. Run with no arguments for interactive mode.

    \b
    Examples:
      python main.py                               # interactive menu
      python main.py https://example.com           # one-shot scan
      python main.py https://example.com --profile stealth --format html
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if not target:
        _interactive()
        return

    # One-shot (non-interactive) mode
    console.print(_BANNER, style="bold cyan")
    findings = _execute_scan(target, profile, fmt, output, crawl, timeout, threads)
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    scan()
