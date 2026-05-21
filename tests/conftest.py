import pytest

BASE_URL = "http://testserver.local"


@pytest.fixture
def base_url():
    return BASE_URL


@pytest.fixture
def clean_finding():
    return {
        "type": "SQL Injection (Error-Based)",
        "url": BASE_URL,
        "severity": "High",
        "details": "Test finding",
    }
