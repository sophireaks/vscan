import hashlib
import logging
import requests
from urllib.parse import urljoin

log = logging.getLogger(__name__)


def _baseline(url: str, timeout: int) -> tuple[int, str] | None:
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        return len(r.content), hashlib.md5(r.content).hexdigest()
    except requests.exceptions.RequestException:
        return None


def _is_soft_404(content: bytes, baseline_size: int, baseline_hash: str) -> bool:
    if hashlib.md5(content).hexdigest() == baseline_hash:
        return True
    ratio = abs(len(content) - baseline_size) / max(baseline_size, 1)
    return ratio < 0.05


def scan_for_sensitive_files(url: str, sensitive_files: list[str], timeout: int = 5) -> dict | None:
    bl = _baseline(url, timeout)

    for file_path in sensitive_files:
        test_url = urljoin(url, file_path.strip("/"))
        try:
            r = requests.get(test_url, timeout=timeout, allow_redirects=True)
        except requests.exceptions.RequestException as exc:
            log.debug("File scan request failed for %s: %s", test_url, exc)
            continue

        if r.status_code != 200:
            continue
        if bl and _is_soft_404(r.content, bl[0], bl[1]):
            log.debug("Soft 404 detected for %s, skipping", test_url)
            continue

        log.debug("Sensitive file found: %s", test_url)
        return {
            "type": "Exposed Sensitive File",
            "url": test_url,
            "severity": "High",
            "cvss": 7.5,
            "details": (
                f"'{file_path}' returned HTTP 200 and is publicly accessible. "
                "This file may contain secrets, credentials, or configuration data (CWE-200)."
            ),
        }
    return None
