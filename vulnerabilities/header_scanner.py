import requests
RECOMMENDED_HEADERS = {
    "Content-Security-Policy": (
        "High",
        "Helps prevent XSS, clickjacking, and other code-injection attacks "
        "by restricting which sources may load.",
    ),
    "Strict-Transport-Security": (
        "High",
        "Forces browsers to use HTTPS, preventing protocol downgrade and "
        "cookie-hijacking attacks.",
    ),
    "X-Content-Type-Options": (
        "Medium",
        "Stops browsers from MIME-sniffing a response away from the declared "
        "content-type, mitigating drive-by XSS.",
    ),
    "X-Frame-Options": (
        "Medium",
        "Prevents the page from being framed by another site (clickjacking).",
    ),
    "Referrer-Policy": (
        "Low",
        "Controls how much referrer information is sent on outbound requests.",
    ),
    "Permissions-Policy": (
        "Low",
        "Restricts which browser features (camera, microphone, geolocation) "
        "the site is permitted to use.",
    ),
}
CRITICAL_HEADERS = {"Content-Security-Policy", "Strict-Transport-Security"}

def check_security_headers(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
    except requests.exceptions.RequestException:
        return None
    missing = [
        (name, sev, why)
        for name, (sev, why) in RECOMMENDED_HEADERS.items()
        if name not in response.headers
    ]
    if not missing:
        return None
    bullet_lines = [f"- {name} ({sev}): {why}" for name, sev, why in missing]
    details = (
        "The response is missing the following recommended security headers "
        "(OWASP Secure Headers, CWE-693):\n" + "\n".join(bullet_lines)
    )
    overall_severity = (
        "High"
        if any(name in CRITICAL_HEADERS for name, _, _ in missing)
        else "Medium"
    )
    return {
        "type": "Missing Security Headers",
        "url": url,
        "severity": overall_severity,
        "cvss": 7.5 if overall_severity == "High" else 5.3,
        "details": details,
    }