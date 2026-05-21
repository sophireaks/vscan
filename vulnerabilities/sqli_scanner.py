import logging
import requests

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
    ("'; SLEEP(5)--",              5, "MySQL"),
    ("' OR SLEEP(5)--",            5, "MySQL"),
    ("'; SELECT pg_sleep(5)--",    5, "PostgreSQL"),
    ("'; WAITFOR DELAY '0:0:5'--", 5, "MSSQL"),
]


def _check_time_based(url: str, timeout: int) -> dict | None:
    """Send sleep payloads; flag if response is significantly slower than baseline."""
    try:
        baseline = resilient_get(url, timeout=timeout)
        baseline_time = baseline.elapsed.total_seconds()
    except requests.exceptions.RequestException:
        return None

    for payload, sleep_secs, db_hint in _TIME_PAYLOADS:
        test_url = f"{url}{payload}"
        try:
            r = resilient_get(test_url, timeout=sleep_secs + timeout)
            elapsed = r.elapsed.total_seconds()
            if elapsed >= sleep_secs * 0.8 and elapsed > baseline_time + 3:
                log.debug("Time-based SQLi at %s (%.1fs delay)", url, elapsed)
                return {
                    "type": "SQL Injection (Time-Based Blind)",
                    "url": url,
                    "severity": "Critical",
                    "cvss": 9.8,
                    "details": (
                        f"Payload '{payload}' caused a {elapsed:.1f}s delay "
                        f"(baseline: {baseline_time:.2f}s). Possible {db_hint} "
                        f"time-based blind SQL injection (CWE-89)."
                    ),
                }
        except requests.exceptions.Timeout:
            log.debug("Timeout on time-based SQLi payload at %s", test_url)
            return {
                "type": "SQL Injection (Time-Based Blind)",
                "url": url,
                "severity": "Critical",
                "cvss": 9.8,
                "details": (
                    f"Payload '{payload}' caused a request timeout "
                    f"(>{sleep_secs + timeout}s). Possible {db_hint} "
                    f"time-based blind SQL injection (CWE-89)."
                ),
            }
        except requests.exceptions.RequestException as exc:
            log.debug("Time-based SQLi request failed for %s: %s", test_url, exc)

    return None


def scan_sqli(url: str, payloads: list[str], timeout: int = 5) -> dict | None:
    """Test for SQL injection: error-based then time-based blind (CWE-89)."""
    for payload in payloads:
        test_url = f"{url}{payload}"
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
                            f"Payload '{payload}' triggered a database error string "
                            f"('{error}'). The application may be vulnerable to SQL injection (CWE-89)."
                        ),
                    }
        except requests.exceptions.RequestException as exc:
            log.debug("SQLi request failed for %s: %s", test_url, exc)

    return _check_time_based(url, timeout)
