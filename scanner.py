import time
import random
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from config import get_sensitive_files
from discovery import get_links
from vulnerabilities.header_scanner import check_security_headers
from vulnerabilities.xss_scanner import scan_xss
from vulnerabilities.sqli_scanner import scan_sqli
from vulnerabilities.file_scanner import scan_for_sensitive_files
from vulnerabilities.bac_scanner import scan_broken_access_control
from vulnerabilities.path_exposure_scanner import scan_path_exposure
from vulnerabilities.cookie_scanner import scan_cookies
from vulnerabilities.cors_scanner import scan_cors
from vulnerabilities.ssl_scanner import scan_ssl
from vulnerabilities.login_bypass_scanner import scan_login_bypass 

log = logging.getLogger(__name__)

XSS_PAYLOADS = [
    '<img src=x onerror=alert("xss")>',
    '<svg/onload=alert("xss")>',
    '<details/open/ontoggle=alert("xss")>',
]

SQLI_PAYLOADS = [
    "' OR 1=1--",
    "' OR '1'='1",
    "') OR ('1'='1",
]

PROFILES = {
    "quick": {
        "scanners": {"headers", "paths", "cookies", "ssl"},
        "intensity": "fast",
        "threads": 5,
    },
    "full": {
        "scanners": {"xss", "sqli", "headers", "files", "paths", "cookies", "bac", "cors", "ssl"},
        "intensity": "fast",
        "threads": 5,
    },
    "stealth": {
        "scanners": {"xss", "sqli", "headers", "files", "paths", "cookies", "bac", "cors", "ssl"},
        "intensity": "stealthy",
        "threads": 2,
    },
}


def _throttle(intensity: str) -> None:
    if intensity == "stealthy":
        time.sleep(random.uniform(1, 3))


def _scan_link(link: str, scan_config: dict) -> list[dict]:
    log.debug("Scanning: %s", link)
    findings: list[dict] = []
    intensity = scan_config.get("scan_intensity", "fast")
    timeout = scan_config.get("timeout", 5)

    custom = scan_config.get("custom_payload")
    xss_payloads = [custom] if custom else XSS_PAYLOADS
    sqli_payloads = [custom] if custom else SQLI_PAYLOADS

    _throttle(intensity)

    if scan_config.get("run_sqli_scan"):
        result = scan_sqli(link, sqli_payloads, timeout)
        if result:
            findings.append(result)

    if scan_config.get("run_xss_scan"):
        result = scan_xss(link, xss_payloads, timeout)
        if result:
            findings.append(result)

    if scan_config.get("run_file_scan"):
        result = scan_for_sensitive_files(link, get_sensitive_files(), timeout)
        if result:
            findings.append(result)

    return findings


def run_scan(target_url: str, scan_config: dict, console=None) -> list[dict]:
    all_findings: list[dict] = []
    timeout = scan_config.get("timeout", 5)

    def _status(msg: str) -> None:
        if console:
            console.print(f"[dim]{msg}[/dim]")
        else:
            log.info(msg)

    _status("[headers] Checking security headers...")
    if scan_config.get("run_header_scan"):
        result = check_security_headers(target_url)
        if result:
            all_findings.append(result)

    _status("[paths] Probing sensitive paths...")
    if scan_config.get("run_path_scan"):
        result = scan_path_exposure(target_url)
        if result:
            all_findings.append(result)

    _status("[cookies] Checking cookie security flags...")
    if scan_config.get("run_cookie_scan"):
        result = scan_cookies(target_url, timeout)
        if result:
            all_findings.append(result)

    _status("[ssl] Checking SSL/TLS configuration...")
    if scan_config.get("run_ssl_scan"):
        result = scan_ssl(target_url, timeout)
        if result:
            all_findings.append(result)

    _status("[cors] Checking CORS policy...")
    if scan_config.get("run_cors_scan"):
        result = scan_cors(target_url, timeout)
        if result:
            all_findings.append(result)

    _status("[bac] Probing privileged paths...")
    if scan_config.get("run_bac_scan"):
        result = scan_broken_access_control(target_url, timeout)
        if result:
            all_findings.append(result)
            
    _status("[login] Testing login bypass...")
    if scan_config.get("run_login_bypass_scan"):
        result = scan_login_bypass(target_url, timeout)
        if result:
            all_findings.append(result)

    use_selenium = scan_config.get("crawl", False)
    _status(f"[discovery] {'Selenium' if use_selenium else 'requests'}-based link discovery...")
    discovered = get_links(target_url, scan_config, use_selenium)
    if target_url not in discovered:
        discovered.append(target_url)
    _status(f"[discovery] Found {len(discovered)} link(s).")

    threads = scan_config.get("threads", 5)

    if console:
        _progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        )
        with _progress:
            task_id = _progress.add_task(
                f"Scanning {len(discovered)} URL(s)...", total=len(discovered)
            )
            with ThreadPoolExecutor(max_workers=threads) as pool:
                futures = {pool.submit(_scan_link, link, scan_config): link for link in discovered}
                for future in as_completed(futures):
                    _progress.advance(task_id)
                    try:
                        all_findings.extend(future.result())
                    except Exception as exc:
                        log.warning("Error scanning %s: %s", futures[future], exc)
    else:
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(_scan_link, link, scan_config): link for link in discovered}
            for future in as_completed(futures):
                try:
                    all_findings.extend(future.result())
                except Exception as exc:
                    log.warning("Error scanning %s: %s", futures[future], exc)

    return all_findings
