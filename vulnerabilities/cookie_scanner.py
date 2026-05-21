import logging
import requests

log = logging.getLogger(__name__)

_REQUIRED_FLAGS = ("HttpOnly", "Secure", "SameSite")


def scan_cookies(url: str, timeout: int = 5) -> dict | None:
    """Check Set-Cookie headers for missing HttpOnly, Secure, and SameSite flags (CWE-614, CWE-1004)."""
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException as exc:
        log.debug("Cookie scan failed for %s: %s", url, exc)
        return None

    set_cookie_headers = [
        v for k, v in response.headers.items() if k.lower() == "set-cookie"
    ]
    if not set_cookie_headers:
        return None

    issues = []
    for cookie_str in set_cookie_headers:
        name = cookie_str.split("=")[0].strip()
        flags_lower = cookie_str.lower()
        missing = [f for f in _REQUIRED_FLAGS if f.lower() not in flags_lower]
        if missing:
            issues.append((name, missing))

    if not issues:
        return None

    details_lines = [
        f"- Cookie '{name}' is missing: {', '.join(flags)}"
        for name, flags in issues
    ]
    return {
        "type": "Insecure Cookie Configuration",
        "url": url,
        "severity": "Medium",
        "cvss": 5.4,
        "details": (
            "One or more cookies are missing security flags (CWE-614, CWE-1004):\n"
            + "\n".join(details_lines)
        ),
    }
