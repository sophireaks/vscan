import hashlib
import requests

SENSITIVE_PATHS = [
    ("/.env",          "Critical", "May leak application secrets, API keys, and DB credentials."),
    ("/.git/config",   "High",     "Exposed Git repo metadata — full source code may be retrievable."),
    ("/.git/HEAD",     "High",     "Confirms .git/ directory is exposed to the public."),
    ("/phpmyadmin/",   "High",     "Database admin UI exposed to the internet."),
    ("/admin/",        "Medium",   "Administrative interface reachable without auth boundary."),
    ("/server-status", "Medium",   "Apache mod_status exposing internal traffic info."),
    ("/server-info",   "Medium",   "Apache mod_info exposing server configuration."),
    ("/.htaccess",     "Medium",   ".htaccess file is being served (it should be denied)."),
    ("/web.config",    "Medium",   "IIS configuration file is being served."),
]
_SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
_CVSS_MAP      = {"Critical": 9.1, "High": 7.5, "Medium": 5.3, "Low": 3.1}


def _baseline(base_url: str, timeout: int) -> tuple[int, str] | None:
    try:
        r = requests.get(base_url, timeout=timeout, allow_redirects=True)
        return len(r.content), hashlib.md5(r.content).hexdigest()
    except requests.exceptions.RequestException:
        return None


def _is_soft_404(content: bytes, baseline_size: int, baseline_hash: str) -> bool:
    if hashlib.md5(content).hexdigest() == baseline_hash:
        return True
    ratio = abs(len(content) - baseline_size) / max(baseline_size, 1)
    return ratio < 0.05


def scan_path_exposure(target_url, timeout: int = 5):
    base = target_url.rstrip("/")
    bl = _baseline(base, timeout)
    found = []

    for path, severity, why in SENSITIVE_PATHS:
        try:
            r = requests.get(base + path, timeout=timeout, allow_redirects=False)
        except requests.exceptions.RequestException:
            continue

        if r.status_code != 200 or len(r.content) <= 50:
            continue
        if bl and _is_soft_404(r.content, bl[0], bl[1]):
            continue

        found.append((path, severity, why, len(r.content)))

    if not found:
        return None

    bullet_lines = [
        f"- {path} ({sev}, {size} bytes): {why}"
        for path, sev, why, size in found
    ]
    details = (
        "The following sensitive paths returned HTTP 200 with non-trivial "
        "content and may be exposed (CWE-200):\n" + "\n".join(bullet_lines)
    )
    overall_severity = max(found, key=lambda f: _SEVERITY_RANK[f[1]])[1]
    return {
        "type": "Sensitive Path Exposure",
        "url": base,
        "severity": overall_severity,
        "cvss": _CVSS_MAP.get(overall_severity, 5.3),
        "details": details,
    }
