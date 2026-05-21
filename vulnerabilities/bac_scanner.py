import logging
import requests

log = logging.getLogger(__name__)

_ADMIN_PATHS = [
    ("/admin", "Administrative interface"),
    ("/admin/", "Administrative interface"),
    ("/api/admin", "Admin API endpoint"),
    ("/api/users", "User listing API"),
    ("/api/v1/users", "User listing API (v1)"),
    ("/wp-admin/", "WordPress admin panel"),
    ("/administrator/", "Joomla admin panel"),
    ("/manage", "Management interface"),
    ("/console", "Admin console"),
    ("/api/config", "Configuration API"),
    ("/actuator", "Spring Boot actuator"),
    ("/actuator/env", "Spring Boot env endpoint"),
]

_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; VScanner/2.0)"}


def scan_broken_access_control(target_url: str, timeout: int = 5) -> dict | None:
    """Probe common admin/privileged paths for unauthenticated access (OWASP A01, CWE-284)."""
    base = target_url.rstrip("/")

    try:
        baseline = requests.get(
            base, timeout=timeout, allow_redirects=True, headers=_HEADERS
        )
        baseline_len = len(baseline.content)
    except requests.exceptions.RequestException as exc:
        log.debug("BAC baseline request failed: %s", exc)
        return None

    exposed = []
    for path, description in _ADMIN_PATHS:
        url = base + path
        try:
            r = requests.get(
                url, timeout=timeout, allow_redirects=True, headers=_HEADERS
            )
        except requests.exceptions.RequestException:
            continue

        if r.status_code == 200 and len(r.content) > 100:
            if abs(len(r.content) - baseline_len) > 200:
                exposed.append((path, description, r.status_code))

    if not exposed:
        return None

    details_lines = [
        f"- {path} ({desc}): HTTP {status}" for path, desc, status in exposed
    ]
    return {
        "type": "Potential Broken Access Control",
        "url": base,
        "severity": "High",
        "cvss": 8.1,
        "details": (
            "The following privileged paths returned HTTP 200 without authentication "
            "(OWASP A01:2021, CWE-284):\n"
            + "\n".join(details_lines)
            + "\n\nManual verification is recommended to confirm these findings."
        ),
    }
