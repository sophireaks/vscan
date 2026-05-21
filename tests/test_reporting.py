"""Unit tests for report generation (JSON, CSV, HTML, terminal)."""

import json
import csv
import io

import pytest
from rich.console import Console

BASE = "http://testserver.local"

SAMPLE_FINDINGS = [
    {"type": "SQL Injection (Error-Based)", "url": BASE, "severity": "High", "details": "SQLi found"},
    {"type": "Missing Security Headers", "url": BASE, "severity": "Medium", "details": "CSP missing"},
    {"type": "Insecure Cookie Configuration", "url": BASE, "severity": "Low", "details": "HttpOnly missing"},
]


class TestJsonReport:
    def setup_method(self):
        from reporting import generate_json_report
        self.generate = generate_json_report

    def test_valid_json(self):
        output = self.generate(SAMPLE_FINDINGS, BASE)
        parsed = json.loads(output)
        assert parsed["meta"]["target"] == BASE
        assert len(parsed["findings"]) == 3

    def test_sorted_by_severity(self):
        output = self.generate(SAMPLE_FINDINGS, BASE)
        findings = json.loads(output)["findings"]
        severities = [f["severity"] for f in findings]
        assert severities == ["High", "Medium", "Low"]

    def test_empty_findings(self):
        output = self.generate([], BASE)
        parsed = json.loads(output)
        assert parsed["meta"]["total_findings"] == 0
        assert parsed["findings"] == []

    def test_meta_fields_present(self):
        output = self.generate(SAMPLE_FINDINGS, BASE)
        meta = json.loads(output)["meta"]
        assert "target" in meta
        assert "generated_at" in meta
        assert "total_findings" in meta


class TestCsvReport:
    def setup_method(self):
        from reporting import generate_csv_report
        self.generate = generate_csv_report

    def test_valid_csv(self):
        output = self.generate(SAMPLE_FINDINGS, BASE)
        reader = list(csv.DictReader(io.StringIO(output)))
        assert len(reader) == 3

    def test_has_required_columns(self):
        output = self.generate(SAMPLE_FINDINGS, BASE)
        reader = csv.DictReader(io.StringIO(output))
        assert set(reader.fieldnames) >= {"severity", "type", "url", "details"}

    def test_sorted_by_severity(self):
        output = self.generate(SAMPLE_FINDINGS, BASE)
        rows = list(csv.DictReader(io.StringIO(output)))
        assert rows[0]["severity"] == "High"
        assert rows[-1]["severity"] == "Low"

    def test_empty_findings_has_header_only(self):
        output = self.generate([], BASE)
        rows = list(csv.DictReader(io.StringIO(output)))
        assert rows == []


class TestHtmlReport:
    def setup_method(self):
        from reporting import generate_html_report
        self.generate = generate_html_report

    def test_returns_html_string(self):
        output = self.generate(SAMPLE_FINDINGS, BASE)
        assert output.strip().startswith("<!DOCTYPE html>")

    def test_contains_target_url(self):
        output = self.generate(SAMPLE_FINDINGS, BASE)
        assert BASE in output

    def test_contains_finding_types(self):
        output = self.generate(SAMPLE_FINDINGS, BASE)
        assert "SQL Injection" in output
        assert "Missing Security Headers" in output

    def test_empty_findings_message(self):
        output = self.generate([], BASE)
        assert "No vulnerabilities found" in output


class TestTerminalReport:
    def setup_method(self):
        from reporting import print_terminal_report
        self.print_report = print_terminal_report

    def test_runs_without_error(self):
        console = Console(file=io.StringIO(), no_color=True)
        self.print_report(SAMPLE_FINDINGS, BASE, console)

    def test_no_findings_message(self):
        buf = io.StringIO()
        console = Console(file=buf, no_color=True)
        self.print_report([], BASE, console)
        output = buf.getvalue()
        assert "No vulnerabilities detected" in output

    def test_findings_appear_in_output(self):
        buf = io.StringIO()
        console = Console(file=buf, no_color=True)
        self.print_report(SAMPLE_FINDINGS, BASE, console)
        output = buf.getvalue()
        # Rich wraps long strings across lines; check for parts that appear on one line
        assert "SQLi found" in output   # details column content
        assert "High" in output
