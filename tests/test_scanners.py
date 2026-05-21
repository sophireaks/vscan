"""Unit tests for all vulnerability scanner modules."""

import re
import responses as resp_mock
import pytest

BASE = "http://testserver.local"

class TestSqliScanner:
    def setup_method(self):
        from vulnerabilities.sqli_scanner import scan_sqli
        self.scan = scan_sqli

    @resp_mock.activate
    def test_detects_mysql_error(self):
        # responses needs a regex to match URLs with special chars from SQLi payloads
        resp_mock.add(
            resp_mock.GET,
            re.compile(re.escape(BASE) + r".*"),
            body="You have an error in your SQL syntax near line 1",
            status=200,
        )
        result = self.scan(BASE, ["' OR 1=1--"])
        assert result is not None
        assert result["severity"] == "High"
        assert "SQL Injection" in result["type"]

    @resp_mock.activate
    def test_no_finding_on_clean_response(self):
        resp_mock.add(
            resp_mock.GET,
            re.compile(re.escape(BASE) + r".*"),
            body="<html>Welcome!</html>",
            status=200,
        )
        assert self.scan(BASE, ["' OR 1=1--"]) is None

    @resp_mock.activate
    def test_returns_none_on_network_error(self):
        import requests
        resp_mock.add(resp_mock.GET, f"{BASE}' OR 1=1--", body=requests.ConnectionError())
        assert self.scan(BASE, ["' OR 1=1--"]) is None

    @resp_mock.activate
    def test_detects_postgresql_error(self):
        resp_mock.add(
            resp_mock.GET,
            re.compile(re.escape(BASE) + r".*"),
            body="ERROR: pg_query() failed: unterminated string literal",
            status=200,
        )
        result = self.scan(BASE, ["' OR 1=1--"])
        assert result is not None
        assert "SQL Injection" in result["type"]

    @resp_mock.activate
    def test_detects_sqlite_error(self):
        resp_mock.add(
            resp_mock.GET,
            re.compile(re.escape(BASE) + r".*"),
            body="sqlite3.OperationalError: unrecognized token",
            status=200,
        )
        result = self.scan(BASE, ["' OR 1=1--"])
        assert result is not None
        assert "SQL Injection" in result["type"]

    def test_detects_time_based_sqli_on_timeout(self):
        from unittest.mock import patch, MagicMock
        import requests as req_lib

        def mock_get(url, **_kw):
            if any(k in url for k in ("SLEEP", "pg_sleep", "WAITFOR")):
                raise req_lib.exceptions.Timeout()
            resp = MagicMock()
            resp.text = "<html>ok</html>"
            resp.elapsed.total_seconds.return_value = 0.2
            resp.status_code = 200
            return resp

        with patch("vulnerabilities.sqli_scanner.resilient_get", side_effect=mock_get):
            result = self.scan(BASE, ["' OR 1=1--"])
        assert result is not None
        assert "Time-Based" in result["type"]
        assert result["severity"] == "Critical"

    def test_detects_time_based_sqli_on_slow_response(self):
        from unittest.mock import patch, MagicMock

        def mock_get(url, **_kw):
            resp = MagicMock()
            resp.text = "<html>ok</html>"
            resp.status_code = 200
            slow = any(k in url for k in ("SLEEP", "pg_sleep", "WAITFOR"))
            resp.elapsed.total_seconds.return_value = 5.5 if slow else 0.2
            return resp

        with patch("vulnerabilities.sqli_scanner.resilient_get", side_effect=mock_get):
            result = self.scan(BASE, ["' OR 1=1--"])
        assert result is not None
        assert "Time-Based" in result["type"]
class TestXssScanner:
    def setup_method(self):
        from vulnerabilities.xss_scanner import scan_xss
        self.scan = scan_xss

    PAYLOAD = '<img src=x onerror=alert(1)>'

    @resp_mock.activate
    def test_detects_xss_in_url_param(self):
        url = f"{BASE}?q=hello"
        resp_mock.add(
            resp_mock.GET,
            re.compile(re.escape(BASE) + r".*"),
            body=f"<html><body>{self.PAYLOAD}</body></html>",
            status=200,
        )
        result = self.scan(url, [self.PAYLOAD])
        assert result is not None
        assert "XSS" in result["type"]
        assert "parameter" in result["details"].lower()

    @resp_mock.activate
    def test_detects_xss_in_get_form(self):
        form_html = (
            '<html><body>'
            '<form action="/search" method="get">'
            '<input type="text" name="q">'
            '</form></body></html>'
        )
        resp_mock.add(resp_mock.GET, BASE, body=form_html, status=200)
        resp_mock.add(
            resp_mock.GET,
            re.compile(re.escape(BASE) + r".*"),
            body=f"<html><body>{self.PAYLOAD}</body></html>",
            status=200,
        )
        result = self.scan(BASE, [self.PAYLOAD])
        assert result is not None
        assert "XSS" in result["type"]

    @resp_mock.activate
    def test_detects_xss_in_post_form(self):
        form_html = (
            '<html><body>'
            '<form action="/submit" method="post">'
            '<input type="text" name="comment">'
            '</form></body></html>'
        )
        resp_mock.add(resp_mock.GET, BASE, body=form_html, status=200)
        resp_mock.add(
            resp_mock.POST,
            re.compile(re.escape(BASE) + r".*"),
            body=f"<html>{self.PAYLOAD}</html>",
            status=200,
        )
        result = self.scan(BASE, [self.PAYLOAD])
        assert result is not None
        assert "XSS" in result["type"]

    @resp_mock.activate
    def test_detects_xss_in_search_type_input(self):
        form_html = (
            '<html><body>'
            '<form action="/search">'
            '<input type="search" name="q">'
            '</form></body></html>'
        )
        resp_mock.add(resp_mock.GET, BASE, body=form_html, status=200)
        resp_mock.add(
            resp_mock.GET,
            re.compile(re.escape(BASE) + r".*"),
            body=f"<html>{self.PAYLOAD}</html>",
            status=200,
        )
        result = self.scan(BASE, [self.PAYLOAD])
        assert result is not None
        assert "XSS" in result["type"]

    @resp_mock.activate
    def test_no_finding_when_payload_not_reflected(self):
        url = f"{BASE}?q=hello"
        resp_mock.add(
            resp_mock.GET,
            re.compile(re.escape(BASE) + r".*"),
            body="<html><body>safe response</body></html>",
            status=200,
        )
        assert self.scan(url, [self.PAYLOAD]) is None

    @resp_mock.activate
    def test_no_finding_when_no_forms_or_params(self):
        resp_mock.add(resp_mock.GET, BASE, body="<html><body>static page</body></html>", status=200)
        assert self.scan(BASE, [self.PAYLOAD]) is None

    @resp_mock.activate
    def test_returns_none_on_network_error(self):
        import requests
        resp_mock.add(resp_mock.GET, BASE, body=requests.ConnectionError())
        assert self.scan(BASE, [self.PAYLOAD]) is None


class TestRateLimiting:
    @resp_mock.activate
    def test_returns_200_response_normally(self):
        from utils import resilient_get
        resp_mock.add(resp_mock.GET, BASE, body="ok", status=200)
        r = resilient_get(BASE, timeout=5)
        assert r.status_code == 200

    @resp_mock.activate
    def test_retries_on_429_and_returns_next_response(self):
        from unittest.mock import patch
        from utils import resilient_get
        resp_mock.add(resp_mock.GET, BASE, body="slow down", status=429,
                      headers={"Retry-After": "1"})
        resp_mock.add(resp_mock.GET, BASE, body="ok", status=200)
        with patch("utils.time.sleep"):
            r = resilient_get(BASE, timeout=5)
        assert r.status_code == 200

    @resp_mock.activate
    def test_raises_on_network_error(self):
        import requests
        from utils import resilient_get
        resp_mock.add(resp_mock.GET, BASE, body=requests.ConnectionError())
        with pytest.raises(requests.exceptions.ConnectionError):
            resilient_get(BASE, timeout=5)


class TestHeaderScanner:
    def setup_method(self):
        from vulnerabilities.header_scanner import check_security_headers
        self.scan = check_security_headers
    @resp_mock.activate
    def test_detects_missing_csp(self):
        resp_mock.add(resp_mock.GET, BASE, body="<html></html>", status=200, headers={})
        result = self.scan(BASE)
        assert result is not None
        assert result["severity"] == "High"
        assert "Content-Security-Policy" in result["details"]
    @resp_mock.activate
    def test_no_finding_when_all_headers_present(self):
        all_headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        resp_mock.add(resp_mock.GET, BASE, body="<html></html>", status=200, headers=all_headers)
        assert self.scan(BASE) is None

    @resp_mock.activate
    def test_medium_severity_when_only_low_headers_missing(self):
        partial_headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        }
        resp_mock.add(resp_mock.GET, BASE, body="<html></html>", status=200, headers=partial_headers)
        result = self.scan(BASE)
        assert result is not None
        assert result["severity"] == "Medium"

    @resp_mock.activate
    def test_returns_none_on_network_error(self):
        import requests
        resp_mock.add(resp_mock.GET, BASE, body=requests.ConnectionError())
        assert self.scan(BASE) is None
class TestPathExposureScanner:
    def setup_method(self):
        from vulnerabilities.path_exposure_scanner import scan_path_exposure
        self.scan = scan_path_exposure

    @resp_mock.activate
    def test_detects_exposed_env_file(self):
        homepage_body = "<html><body>Welcome</body></html>"
        env_body = "DB_PASSWORD=supersecret\nAPI_KEY=abc123xyz\nSECRET_KEY=aaabbbccc\n"
        resp_mock.add(resp_mock.GET, BASE, body=homepage_body, status=200)
        resp_mock.add(resp_mock.GET, f"{BASE}/.env", body=env_body, status=200)
        result = self.scan(BASE)
        assert result is not None
        assert result["severity"] in ("Critical", "High")
        assert "/.env" in result["details"]

    @resp_mock.activate
    def test_ignores_soft_404(self):
        # Server returns the homepage body for every path — classic soft 404
        homepage_body = "<html><body>Page not found</body></html>"
        resp_mock.add(resp_mock.GET, re.compile(re.escape(BASE) + r".*"), body=homepage_body, status=200)
        assert self.scan(BASE) is None

    @resp_mock.activate
    def test_ignores_redirect(self):
        resp_mock.add(resp_mock.GET, BASE, body="<html>home</html>", status=200)
        resp_mock.add(resp_mock.GET, f"{BASE}/.env", body="", status=301, headers={"Location": "/login"})
        assert self.scan(BASE) is None

    @resp_mock.activate
    def test_ignores_tiny_response(self):
        resp_mock.add(resp_mock.GET, BASE, body="<html>home</html>", status=200)
        resp_mock.add(resp_mock.GET, f"{BASE}/.env", body="x", status=200)
        assert self.scan(BASE) is None
class TestCookieScanner:
    def setup_method(self):
        from vulnerabilities.cookie_scanner import scan_cookies
        self.scan = scan_cookies

    @resp_mock.activate
    def test_detects_missing_httponly(self):
        resp_mock.add(
            resp_mock.GET, BASE, body="ok", status=200,
            headers={"Set-Cookie": "session=abc123; Path=/; Secure; SameSite=Lax"},
        )
        result = self.scan(BASE)
        assert result is not None
        assert "HttpOnly" in result["details"]

    @resp_mock.activate
    def test_detects_missing_secure_flag(self):
        resp_mock.add(
            resp_mock.GET, BASE, body="ok", status=200,
            headers={"Set-Cookie": "session=abc123; HttpOnly; SameSite=Lax"},
        )
        result = self.scan(BASE)
        assert result is not None
        assert "Secure" in result["details"]

    @resp_mock.activate
    def test_no_finding_when_flags_present(self):
        resp_mock.add(
            resp_mock.GET, BASE, body="ok", status=200,
            headers={"Set-Cookie": "session=abc123; HttpOnly; Secure; SameSite=Lax"},
        )
        assert self.scan(BASE) is None

    @resp_mock.activate
    def test_no_finding_when_no_cookies(self):
        resp_mock.add(resp_mock.GET, BASE, body="ok", status=200)
        assert self.scan(BASE) is None

    @resp_mock.activate
    def test_detects_missing_samesite(self):
        resp_mock.add(
            resp_mock.GET, BASE, body="ok", status=200,
            headers={"Set-Cookie": "session=abc123; HttpOnly; Secure"},
        )
        result = self.scan(BASE)
        assert result is not None
        assert "SameSite" in result["details"]

    @resp_mock.activate
    def test_returns_none_on_network_error(self):
        import requests
        resp_mock.add(resp_mock.GET, BASE, body=requests.ConnectionError())
        assert self.scan(BASE) is None
class TestFileScanner:
    def setup_method(self):
        from vulnerabilities.file_scanner import scan_for_sensitive_files
        self.scan = scan_for_sensitive_files

    @resp_mock.activate
    def test_detects_exposed_env(self):
        homepage_body = "<html><body>Welcome</body></html>"
        env_body = "DB_PASSWORD=secret\nAPI_KEY=abc123\nSECRET=xyz\n"
        resp_mock.add(resp_mock.GET, BASE, body=homepage_body, status=200)
        resp_mock.add(resp_mock.GET, f"{BASE}/.env", body=env_body, status=200)
        result = self.scan(BASE, [".env"])
        assert result is not None
        assert result["severity"] == "High"

    @resp_mock.activate
    def test_no_finding_on_404(self):
        resp_mock.add(resp_mock.GET, BASE, body="<html>home</html>", status=200)
        resp_mock.add(resp_mock.GET, f"{BASE}/.env", body="Not Found", status=404)
        assert self.scan(BASE, [".env"]) is None

    @resp_mock.activate
    def test_no_finding_on_soft_404(self):
        homepage_body = "<html><body>Page not found</body></html>"
        resp_mock.add(resp_mock.GET, re.compile(re.escape(BASE) + r".*"), body=homepage_body, status=200)
        assert self.scan(BASE, [".env"]) is None
class TestBacScanner:
    def setup_method(self):
        from vulnerabilities.bac_scanner import scan_broken_access_control
        self.scan = scan_broken_access_control

    @resp_mock.activate
    def test_detects_exposed_admin(self):
        # Baseline (homepage)
        resp_mock.add(resp_mock.GET, BASE, body="<html>Home</html>", status=200)
        # Admin path returns different, substantial content
        resp_mock.add(
            resp_mock.GET, f"{BASE}/admin",
            body="<html>" + "Admin dashboard content " * 30 + "</html>",
            status=200,
        )
        result = self.scan(BASE)
        assert result is not None
        assert "/admin" in result["details"]
    @resp_mock.activate
    def test_no_finding_when_admin_returns_401(self):
        resp_mock.add(resp_mock.GET, BASE, body="<html>Home</html>", status=200)
        for path in ["/admin", "/admin/", "/api/admin", "/api/users", "/api/v1/users",
                     "/wp-admin/", "/administrator/", "/manage", "/console",
                     "/api/config", "/actuator", "/actuator/env"]:
            resp_mock.add(resp_mock.GET, f"{BASE}{path}", body="Unauthorized", status=401)
        assert self.scan(BASE) is None

    @resp_mock.activate
    def test_no_finding_when_admin_redirects_to_login(self):
        resp_mock.add(resp_mock.GET, BASE, body="<html>Home</html>", status=200)
        for path in ["/admin", "/admin/", "/api/admin", "/api/users", "/api/v1/users",
                     "/wp-admin/", "/administrator/", "/manage", "/console",
                     "/api/config", "/actuator", "/actuator/env"]:
            resp_mock.add(resp_mock.GET, f"{BASE}{path}", body="",
                          status=302, headers={"Location": "/login"})
        assert self.scan(BASE) is None

    @resp_mock.activate
    def test_no_finding_when_admin_content_matches_baseline(self):
        body = "<html><body>Welcome to our site</body></html>"
        resp_mock.add(resp_mock.GET, re.compile(re.escape(BASE) + r".*"), body=body, status=200)
        assert self.scan(BASE) is None

    def test_finding_has_cvss_score(self):
        from vulnerabilities.bac_scanner import scan_broken_access_control
        import responses as r
        with r.RequestsMock() as m:
            m.add(r.GET, BASE, body="<html>Home</html>", status=200)
            m.add(r.GET, f"{BASE}/admin",
                  body="<html>" + "Admin dashboard content " * 30 + "</html>", status=200)
            result = scan_broken_access_control(BASE)
            assert result is not None
            assert "cvss" in result
            assert result["cvss"] == 8.1


# ── CORS scanner ──────────────────────────────────────────────────────────────

class TestCorsScanner:
    def setup_method(self):
        from vulnerabilities.cors_scanner import scan_cors
        self.scan = scan_cors

    @resp_mock.activate
    def test_detects_wildcard_acao(self):
        resp_mock.add(
            resp_mock.GET, BASE, body="ok", status=200,
            headers={"Access-Control-Allow-Origin": "*"},
        )
        result = self.scan(BASE)
        assert result is not None
        assert "CORS" in result["type"]
        assert result["severity"] == "High"
        assert result["cvss"] == 7.5

    @resp_mock.activate
    def test_detects_reflected_origin_with_credentials(self):
        resp_mock.add(
            resp_mock.GET, BASE, body="ok", status=200,
            headers={
                "Access-Control-Allow-Origin": "https://evil-attacker.com",
                "Access-Control-Allow-Credentials": "true",
            },
        )
        result = self.scan(BASE)
        assert result is not None
        assert result["severity"] == "Critical"
        assert result["cvss"] == 9.1

    @resp_mock.activate
    def test_no_finding_when_no_acao_header(self):
        resp_mock.add(resp_mock.GET, BASE, body="ok", status=200)
        assert self.scan(BASE) is None

    @resp_mock.activate
    def test_no_finding_on_trusted_origin(self):
        resp_mock.add(
            resp_mock.GET, BASE, body="ok", status=200,
            headers={"Access-Control-Allow-Origin": "https://trusted-site.com"},
        )
        assert self.scan(BASE) is None


# ── SSL scanner ───────────────────────────────────────────────────────────────

class TestSslScanner:
    def setup_method(self):
        from vulnerabilities.ssl_scanner import scan_ssl
        self.scan = scan_ssl

    @resp_mock.activate
    def test_detects_missing_https_redirect(self):
        http_url = "http://testserver.local"
        resp_mock.add(resp_mock.GET, http_url, body="ok", status=200)
        result = self.scan(http_url)
        assert result is not None
        assert "HTTPS" in result["details"]
        assert result["severity"] == "Medium"

    @resp_mock.activate
    def test_no_finding_when_http_redirects_to_https(self):
        http_url = "http://testserver.local"
        resp_mock.add(
            resp_mock.GET, http_url, body="", status=301,
            headers={"Location": "https://testserver.local"},
        )
        assert self.scan(http_url) is None

    @resp_mock.activate
    def test_returns_none_on_network_error(self):
        import requests
        resp_mock.add(resp_mock.GET, "http://testserver.local", body=requests.ConnectionError())
        assert self.scan("http://testserver.local") is None

    def test_no_finding_for_https_with_valid_cert(self):
        from unittest.mock import patch
        with patch("vulnerabilities.ssl_scanner._check_cert", return_value=[]):
            result = self.scan("https://testserver.local")
        assert result is None

    def test_detects_expired_cert(self):
        from unittest.mock import patch
        with patch("vulnerabilities.ssl_scanner._check_cert",
                   return_value=["Certificate EXPIRED on 2024-01-01"]):
            result = self.scan("https://testserver.local")
        assert result is not None
        assert result["severity"] == "High"
        assert "EXPIRED" in result["details"]
