import logging
import requests

log = logging.getLogger(__name__)

_EVIL_ORIGIN = "https://evil-attacker.com"


def scan_cors(url: str, timeout: int = 5) -> dict | None:
    """Probe CORS policy for wildcard or reflected-origin misconfigurations (CWE-942, OWASP A05)."""
    try:
        response = requests.get(
            url, timeout=timeout,
            headers={"Origin": _EVIL_ORIGIN},
            allow_redirects=True,
        )
    except requests.exceptions.RequestException as exc:
        log.debug("CORS scan failed for %s: %s", url, exc)
        return None

    acao = response.headers.get("Access-Control-Allow-Origin", "")
    acac = response.headers.get("Access-Control-Allow-Credentials", "").strip().lower()

    if not acao:
        return None

    issues = []
    severity = "Medium"
    cvss = 5.4

    if acao == "*":
        issues.append("Wildcard ACAO (*) allows any origin to read responses")
        severity = "High"
        cvss = 7.5
    elif acao == _EVIL_ORIGIN:
        issues.append(f"Server reflects arbitrary Origin header ('{_EVIL_ORIGIN}')")
        severity = "High"
        cvss = 7.5
        if acac == "true":
            issues.append(
                "Access-Control-Allow-Credentials: true with reflected origin — "
                "authenticated cross-origin requests are possible"
            )
            severity = "Critical"
            cvss = 9.1

    if not issues:
        return None

    return {
        "type": "CORS Misconfiguration",
        "url": url,
        "severity": severity,
        "cvss": cvss,
        "details": (
            "CORS policy issues detected (CWE-942, OWASP A05:2021):\n"
            + "\n".join(f"- {i}" for i in issues)
        ),
    }
