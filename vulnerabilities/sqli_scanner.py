import logging
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from utils import resilient_get

log = logging.getLogger(__name__)

_SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate[",
    "syntax error",
    "pg_query",
    "sqlite3.operationalerror",
]

_TIME_PAYLOADS = [
    ("' AND SLEEP(5)--",            5, "MySQL"),
    ("' OR SLEEP(5)--",             5, "MySQL"),
    ("' AND pg_sleep(5)--",         5, "PostgreSQL"),
    ("'; WAITFOR DELAY '0:0:5'--",  5, "MSSQL"),
]


def _inject_param(url: str, param: str, payload: str) -> str:
    """Return a new URL with `payload` substituted into `param`."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    injected = {k: v[:] for k, v in params.items()}
    injected[param] = [payload]
    return urlunparse(parsed._replace(query=urlencode(injected, doseq=True)))


def _check_error_based(url: str, payloads: list[str], timeout: int) -> dict | None:
    """Inject each payload into every query parameter; look for DB error strings."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        log.debug("SQLi error-based: no query params in %s, skipping", url)
        return None

    for param_name in params:
        for payload in payloads:
            test_url = _inject_param(url, param_name, payload)
            try:
                response = resilient_get(test_url, timeout=timeout)
                body_lower = response.text.lower()
                for error in _SQL_ERRORS:
                    if error in body_lower:
                        log.debug("SQLi indicator '%s' found at %s", error, test_url)
                        return {
                            "type": "SQL Injection (Error-Based)",
                            "url": url,
                            "severity": "High",
                            "cvss": 9.8,
                            "details": (
                                f"Parameter '{param_name}' with payload '{payload}' triggered "
                                f"a database error string ('{error}'). "
                                f"The application may be vulnerable to SQL injection (CWE-89)."
                            ),
                        }
            except requests.exceptions.RequestException as exc:
                log.debug("SQLi error-based request failed for %s: %s", test_url, exc)

    return None


def _check_time_based(url: str, timeout: int) -> dict | None:
    """Inject sleep payloads into every query parameter; flag significant delays."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        log.debug("SQLi time-based: no query params in %s, skipping", url)
        return None

    # Establish baseline response time
    try:
        baseline = resilient_get(url, timeout=timeout)
        baseline_time = baseline.elapsed.total_seconds()
    except requests.exceptions.RequestException:
        return None

    for param_name in params:
        for payload, sleep_secs, db_hint in _TIME_PAYLOADS:
            test_url = _inject_param(url, param_name, payload)
            try:
                r = resilient_get(test_url, timeout=sleep_secs + timeout)
                elapsed = r.elapsed.total_seconds()
                if elapsed >= sleep_secs * 0.8 and elapsed > baseline_time + 3:
                    log.debug("Time-based SQLi at %s param '%s' (%.1fs delay)", url, param_name, elapsed)
                    return {
                        "type": "SQL Injection (Time-Based Blind)",
                        "url": url,
                        "severity": "Critical",
                        "cvss": 9.8,
                        "details": (
                            f"Parameter '{param_name}' with payload '{payload}' caused a "
                            f"{elapsed:.1f}s delay (baseline: {baseline_time:.2f}s). "
                            f"Possible {db_hint} time-based blind SQL injection (CWE-89)."
                        ),
                    }
            except requests.exceptions.Timeout:
                log.debug("Timeout on time-based SQLi at %s param '%s'", test_url, param_name)
                return {
                    "type": "SQL Injection (Time-Based Blind)",
                    "url": url,
                    "severity": "Critical",
                    "cvss": 9.8,
                    "details": (
                        f"Parameter '{param_name}' with payload '{payload}' caused a request "
                        f"timeout (>{sleep_secs + timeout}s). "
                        f"Possible {db_hint} time-based blind SQL injection (CWE-89)."
                    ),
                }
            except requests.exceptions.RequestException as exc:
                log.debug("Time-based SQLi request failed for %s: %s", test_url, exc)

    return None


def scan_sqli(url: str, payloads: list[str], timeout: int = 5) -> dict | None:
    """Test for SQL injection: error-based then time-based blind (CWE-89).

    Payloads are injected into existing URL query parameters only.
    URLs with no query string are skipped (nothing to inject into).
    """
    result = _check_error_based(url, payloads, timeout)
    if result:
        return result
    return _check_time_based(url, timeout)
