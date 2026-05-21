import logging
import ssl
import socket
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse

log = logging.getLogger(__name__)

_EXPIRY_WARNING_DAYS = 30


def _check_cert(hostname: str, port: int, timeout: int) -> list[str]:
    issues = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
                not_after_str = cert.get("notAfter", "")
                if not_after_str:
                    not_after = datetime.strptime(
                        not_after_str, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    days_left = (not_after - datetime.now(tz=timezone.utc)).days
                    if days_left < 0:
                        issues.append(f"Certificate EXPIRED on {not_after.date()}")
                    elif days_left < _EXPIRY_WARNING_DAYS:
                        issues.append(
                            f"Certificate expires in {days_left} day(s) on {not_after.date()}"
                        )
    except ssl.SSLCertVerificationError as exc:
        issues.append(f"Certificate validation failed: {exc.reason}")
    except ssl.SSLError as exc:
        issues.append(f"SSL/TLS error: {exc}")
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return issues


def scan_ssl(url: str, timeout: int = 5) -> dict | None:
    """Check for missing HTTPS redirect and certificate issues (CWE-295, CWE-319)."""
    parsed = urlparse(url)
    issues = []

    if parsed.scheme == "http":
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=False)
            location = r.headers.get("Location", "")
            if r.status_code not in (301, 302, 307, 308) or not location.startswith("https"):
                issues.append(
                    "No HTTP→HTTPS redirect — traffic can be intercepted in plaintext (CWE-319)"
                )
        except requests.exceptions.RequestException as exc:
            log.debug("SSL HTTP redirect check failed: %s", exc)

    if parsed.scheme == "https":
        hostname = parsed.hostname
        port = parsed.port or 443
        issues.extend(_check_cert(hostname, port, timeout))

    if not issues:
        return None

    severity = "High" if any("EXPIRED" in i or "failed" in i for i in issues) else "Medium"
    return {
        "type": "SSL/TLS Issue",
        "url": url,
        "severity": severity,
        "cvss": 7.5 if severity == "High" else 5.9,
        "details": (
            "SSL/TLS configuration issues found (CWE-295, CWE-319):\n"
            + "\n".join(f"- {i}" for i in issues)
        ),
    }
