import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from utils import resilient_get

log = logging.getLogger(__name__)

_FINDING = {
    "type": "Cross-Site Scripting (XSS)",
    "severity": "High",
    "cvss": 6.1,
}

_TEXT_INPUT_TYPES = {"text", "search", "email", "url", "tel", "number", "password"}


def _test_url_params(url: str, payloads: list[str], timeout: int) -> dict | None:
    """Inject payloads into each existing URL query parameter and check for reflection."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return None

    for param_name in params:
        for payload in payloads:
            injected = {k: v[:] for k, v in params.items()}
            injected[param_name] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(injected, doseq=True)))
            try:
                r = resilient_get(test_url, timeout=timeout)
                if payload in r.text:
                    return {
                        **_FINDING,
                        "url": url,
                        "details": (
                            f"URL parameter '{param_name}' reflects payload without encoding: "
                            f"'{payload}'. Vulnerable to reflected XSS (CWE-79)."
                        ),
                    }
            except requests.exceptions.RequestException as exc:
                log.debug("XSS URL param test failed for %s: %s", test_url, exc)
    return None


def scan_xss(url: str, payloads: list[str], timeout: int = 5) -> dict | None:
    """Test URL parameters and HTML form inputs for reflected XSS (CWE-79)."""
    result = _test_url_params(url, payloads, timeout)
    if result:
        return result

    try:
        response = resilient_get(url, timeout=timeout)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            return None

        for form in forms:
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            text_inputs = [
                inp
                for inp in form.find_all(["input", "textarea"])
                if inp.get("name") and (
                    inp.name == "textarea" or
                    inp.get("type", "text").lower() in _TEXT_INPUT_TYPES
                )
            ]
            if not text_inputs:
                continue

            for payload in payloads:
                data = {inp["name"]: payload for inp in text_inputs}
                submit_url = urljoin(url, action)
                try:
                    if method == "post":
                        res = requests.post(submit_url, data=data, timeout=timeout)
                    else:
                        res = resilient_get(submit_url, params=data, timeout=timeout)

                    if payload in res.text:
                        return {
                            **_FINDING,
                            "url": url,
                            "details": (
                                f"Form at '{submit_url}' reflects payload without encoding: "
                                f"'{payload}'. Likely vulnerable to reflected XSS (CWE-79)."
                            ),
                        }
                except requests.exceptions.RequestException as exc:
                    log.debug("XSS form submission failed for %s: %s", submit_url, exc)
    except requests.exceptions.RequestException as exc:
        log.debug("XSS scan failed for %s: %s", url, exc)
    return None
