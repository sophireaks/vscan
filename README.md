# vscan — Terminal Vulnerability Scanner

A modular, **CLI-first** web vulnerability scanner written in Python. Built to practice secure software design, concurrent task execution, and structured security reporting.

> **Non-destructive by design — passive observation and safe probing only.**
> Only scan systems you own or have explicit written permission to test.

---

## Features

| Feature | Detail |
|---|---|
| 9 scanner modules | SQLi, XSS, headers, sensitive files, path exposure, cookies, BAC, CORS, SSL/TLS |
| Interactive menu | Numbered menu on launch — pick scan type or build a custom scanner set |
| CVSS 3.1 scores | Every finding carries a CVSS base score |
| Scan profiles | `quick` / `full` / `stealth` presets, or select scanners individually |
| Rich terminal output | Colour-coded findings table with CVSS column and severity summary |
| Multi-format export | JSON, CSV, HTML report output with auto-timestamp filenames |
| Concurrent scanning | `ThreadPoolExecutor` with configurable thread count |
| Selenium crawler | Optional JS-aware link discovery (falls back to `requests`) |
| `.env` config | Secrets and defaults kept out of source code |
| 63 unit tests | Full `pytest` suite with mocked HTTP (zero real network calls) |
| CI-friendly exit codes | Exits `1` when findings are found — drop straight into a pipeline |
| Docker support | Single-line container run |

---

## Scanners

| # | Module | Checks | OWASP / CWE |
|---|---|---|---|
| 1 | `xss_scanner` | Reflected XSS in URL parameters and HTML form inputs | CWE-79 |
| 2 | `sqli_scanner` | Error-based and time-based blind SQL injection | CWE-89 |
| 3 | `header_scanner` | Missing CSP, HSTS, X-Frame-Options, etc. | CWE-693 |
| 4 | `file_scanner` | Publicly accessible config / backup files | CWE-200 |
| 5 | `path_exposure_scanner` | Exposed `.env`, `.git/`, phpMyAdmin, etc. | CWE-200 |
| 6 | `cookie_scanner` | Missing `HttpOnly`, `Secure`, `SameSite` flags | CWE-614, CWE-1004 |
| 7 | `bac_scanner` | Unauthenticated access to admin/API endpoints | CWE-284, OWASP A01 |
| 8 | `cors_scanner` | Wildcard or reflected-origin CORS headers | CWE-942, OWASP A05 |
| 9 | `ssl_scanner` | Missing HTTPS redirect, expired/invalid cert | CWE-295, CWE-319 |

---

## Tech Stack

| Component | Tool |
|---|---|
| Language | Python 3.11+ |
| CLI | Click |
| Terminal UI | Rich |
| HTTP client | Requests |
| HTML parsing | BeautifulSoup4 |
| Browser automation | Selenium (optional) |
| Config | python-dotenv |
| Tests | pytest + responses |

---

## Project Structure

```text
.
├── main.py                      # CLI entry point — interactive menu + one-shot mode
├── scanner.py                   # Orchestrator: thread pool, progress bar, scan profiles
├── discovery.py                 # Link discovery (requests or Selenium crawler)
├── reporting.py                 # Terminal table, JSON, CSV, HTML report generators
├── config.py                    # Loads sensitive file list from config.ini
├── utils.py                     # resilient_get() — HTTP with 429 rate-limit retry
│
├── vulnerabilities/
│   ├── xss_scanner.py           # Reflected XSS — URL params + HTML form inputs
│   ├── sqli_scanner.py          # SQL injection — error-based + time-based blind
│   ├── header_scanner.py        # Missing CSP, HSTS, X-Frame-Options, etc.
│   ├── file_scanner.py          # Exposed config/backup files (.env, .bak, etc.)
│   ├── path_exposure_scanner.py # Exposed paths (.git/, phpMyAdmin, /admin, etc.)
│   ├── cookie_scanner.py        # Missing HttpOnly, Secure, SameSite flags
│   ├── bac_scanner.py           # Broken access control — admin/API endpoints
│   ├── cors_scanner.py          # CORS misconfiguration — wildcard or reflected origin
│   └── ssl_scanner.py           # Missing HTTPS redirect, expired/invalid certificate
│
├── tests/
│   ├── conftest.py              # Shared pytest fixtures
│   ├── test_scanners.py         # 48 scanner unit tests (zero real network calls)
│   └── test_reporting.py        # 15 report generation tests
│
├── config.ini                   # Sensitive file list for file_scanner
├── .env.example                 # Environment variable template
├── requirements.txt
├── Dockerfile
└── SECURITY.md
```

---

## Getting Started

### Prerequisites

- Python 3.11+
- A target you are **authorised** to scan (e.g. a local VM, TryHackMe / HackTheBox machine, or DVWA)

### Installation

```bash
git clone https://github.com/sophireaks/Vulnerability-Scanner.git
cd Vulnerability-Scanner

python -m venv .venv
# Linux/Mac:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

pip install -r requirements.txt
cp .env.example .env
```

### Usage

**Interactive mode** (default — just run with no arguments):
```bash
python main.py
```

A numbered menu appears on launch:

```
  ╭────┬────────────────┬───────────────────────────────────────╮
  │ 1  │ Quick Scan     │ headers, paths, cookies, ssl (fastest)│
  │ 2  │ Full Scan      │ all 9 scanners               (default)│
  │ 3  │ Stealth Scan   │ all 9 scanners + slow delays (evasive)│
  │ 4  │ Custom Scan    │ choose individual scanners            │
  │    │                │                                       │
  │ Q  │ Quit           │                                       │
  ╰────┴────────────────┴───────────────────────────────────────╯

  Choice [2]:
```

Choosing **Custom Scan (4)** shows a scanner picker:

```
  ┌───┬──────────┬────────────────────────────────────┬──────────┐
  │ # │ Scanner  │ Checks                             │ Ref      │
  ├───┼──────────┼────────────────────────────────────┼──────────┤
  │ 1 │ xss      │ Reflected XSS in HTML forms      ` │ CWE-79   │
  │ 2 │ sqli     │ Error-based SQL injection          │ CWE-89   │
  │ 3 │ headers  │ Missing security headers           │ CWE-693  │
  │ 4 │ files    │ Sensitive file exposure            │ CWE-200  │
  │ 5 │ paths    │ Path/directory exposure            │ CWE-200  │
  │ 6 │ cookies  │ Insecure cookie flags              │ CWE-614  │
  │ 7 │ bac      │ Broken access control              │ CWE-284  │
  │ 8 │ cors     │ CORS misconfiguration              │ CWE-942  │
  │ 9 │ ssl      │ SSL/TLS configuration issues       │ CWE-295  │
  └───┴──────────┴────────────────────────────────────┴──────────┘

  Select scanners (comma-separated numbers e.g. 1,3,5 — or 'all' / 'back'):
```

**One-shot CLI mode** (non-interactive):
```bash
# Scan with full profile
python main.py https://target.example.com

# Use a specific profile
python main.py https://target.example.com --profile stealth

# Save an HTML or JSON report
python main.py https://target.example.com --format html
python main.py https://target.example.com --format json --output report.json

# With Selenium crawler
python main.py https://target.example.com --crawl --threads 3

# All options
python main.py --help
```

### Example output

```
██╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██║   ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
██║   ██║███████╗██║     ███████║██╔██╗ ██║
╚██╗ ██╔╝╚════██║██║     ██╔══██║██║╚██╗██║
 ╚████╔╝ ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═══╝  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
         Web Vulnerability Scanner  v2.0

╭─ Scan Configuration ─────────────────────────────────────────────╮
│ Target:    https://target.example.com                            │
│ Profile:   full                                                  │
│ Scanners:  bac, cookies, cors, files, headers, paths, sqli, ssl, │
│            xss                                                   │
│ Intensity: fast   Threads: 5   Crawl: no                         │
╰──────────────────────────────────────────────────────────────────╯

╭──────────┬──────┬───────────────────────────┬───────────────────────────╮
│ Severity │ CVSS │ Type                      │ Details                   │
├──────────┼──────┼───────────────────────────┼───────────────────────────┤
│   High   │ 7.5  │ Missing Security Headers  │ CSP, HSTS missing ...     │
│  Medium  │ 5.4  │ Insecure Cookie Config    │ session missing HttpOnly  │
╰──────────┴──────┴───────────────────────────┴───────────────────────────╯

Summary: 1 High/Critical  1 Medium  0 Low  (2 total)
```

---

## Running Tests

```bash
python -m pytest tests/ -v
```

All 63 tests pass with no network calls (HTTP responses are fully mocked with `responses`).

---

## Docker

```bash
docker build -t vscan .
docker run --rm vscan https://target.example.com --format json
```

---

## Configuration

| Method | How |
|---|---|
| `.env` file | Copy `.env.example` → `.env`, fill in values |
| `config.ini` | Customise the list of sensitive files to probe |
| CLI flags | Override any setting per-run (see `--help`) |
| Environment variables | `SCAN_AUTH_USER`, `SCAN_AUTH_PASS`, `SCAN_TIMEOUT`, `SCAN_THREADS` |

---

## Responsible Use

Read [`SECURITY.md`](./SECURITY.md) before using this tool.

- Only scan systems you own or have **written** permission to test.
- All checks are non-destructive by design.
- The author accepts no responsibility for misuse.
- Unauthorised scanning is illegal in most jurisdictions.

---

## Author

**Sophireak Soeng** — IT Engineering student at Royal University of Phnom Penh, passionate about cybersecurity and building practical security tools.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/sophireak-soeng-10b668265/)
[![TryHackMe](https://img.shields.io/badge/TryHackMe-212C42?style=flat&logo=tryhackme&logoColor=white)](https://tryhackme.com/p/Sophireak.S)
[![Email](https://img.shields.io/badge/Email-D14836?style=flat&logo=gmail&logoColor=white)](mailto:sophireaksoeng@gmail.com)

---

## License

MIT License — see `LICENSE` for details.
