# url-scanner

A lightweight, **passive and non-destructive** URL / website reconnaissance tool, written in Python.

It answers a simple question — *"what does this website reveal about itself over a normal HTTP request?"* — without ever attempting exploitation, brute forcing, fuzzing, or anything an ordinary browser wouldn't already do.

```
python main.py https://example.com
```

```
============================================================
Target: https://example.com
============================================================
DNS        ✔  93.184.216.34  (12.4 ms)
HTTP       200  (88.1 ms, text/html; charset=UTF-8)
TLS        TLSv1.3  expires 2026-11-03T12:00:00+00:00  (76 days left)
           issuer: C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1
Headers    grade C  (4/8 security headers set)
Tech hints Server: ECS (nyb/1D2A)
```

## Why this exists

This is a portfolio project demonstrating practical, defensible security tooling: the kind of read-only recon a pentester, bug bounty hunter, or site owner runs *before* deciding what (if anything) to test further. It deliberately stops short of active testing.

## Features

- **URL validation & normalization** — scheme/host sanity checks, no network required.
- **DNS resolution** — A/AAAA records and resolution timing.
- **HTTP inspection** — status code, full redirect chain, response timing, content type/length.
- **TLS certificate analysis** — issuer, subject, SANs, protocol/cipher, expiry countdown.
- **Security header audit** — checks for `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and the `Cross-Origin-*` isolation headers, with an A–F grade.
- **Cookie flag analysis** — flags cookies missing `Secure`, `HttpOnly`, or `SameSite`.
- **Lightweight technology fingerprinting** — passive hints from `Server`/`X-Powered-By`/etc. headers and well-known cookie names (PHP, Django, Rails, WordPress, Laravel, Cloudflare, Shopify, ...).
- **Batch scanning** — point it at a text file of URLs and it scans them concurrently.
- **JSON output** — for piping into other tools, dashboards, or CI.

### What it deliberately does *not* do

No exploitation, no payload injection, no credential brute forcing, no port scanning, no directory bruteforcing, no denial-of-service testing. It sends one standard `GET` request per target with a descriptive `User-Agent` and reads what the server volunteers. See [`FAQ.md`](FAQ.md) for the full ethics/legality discussion.

## Installation

```bash
git clone https://github.com/your-username/url-scanner.git
cd url-scanner
pip install -r requirements.txt
```

Requires Python 3.10+. The only runtime dependency is [`requests`](https://pypi.org/project/requests/) — everything else (DNS, TLS, cookie parsing) uses the standard library.

## Usage

```bash
# Basic scan
python main.py https://example.com

# Full security header breakdown
python main.py https://example.com --headers

# Machine-readable JSON to stdout
python main.py https://example.com --json

# Scan a list of URLs concurrently, save results
python main.py urls.txt --output results.json

# Tune concurrency / timeout for batch scans
python main.py urls.txt --concurrency 10 --timeout 5 --output results.json

# Skip TLS certificate inspection (faster, DNS/HTTP/headers only)
python main.py https://example.com --no-tls
```

`urls.txt` is a plain text file, one URL per line (`#`-prefixed lines are treated as comments and skipped):

```
https://example.com
https://github.com
# staging.example.com is currently down
```

### CLI reference

```
usage: url-scanner [-h] [--json] [--headers] [-o FILE] [-t TIMEOUT]
                    [-c CONCURRENCY] [--no-tls] [-v] [--version]
                    target

positional arguments:
  target                A single URL, or a path to a file with one URL per line

options:
  -h, --help            show this help message and exit
  --json                Print raw JSON instead of a formatted report
  --headers             Include the full security header breakdown
  -o FILE, --output FILE
                        Write full JSON results to FILE
  -t TIMEOUT, --timeout TIMEOUT
                        Per-request timeout in seconds (default: 10)
  -c CONCURRENCY, --concurrency CONCURRENCY
                        Concurrent scans for batch targets (default: 5)
  --no-tls              Skip TLS certificate inspection
  -v, --verbose         Enable verbose logging
  --version             show program's version number and exit
```

## Project layout

```
url-scanner/
├── url_scanner/
│   ├── __init__.py       # package metadata, public API
│   ├── scanner.py        # orchestration: DNS, HTTP, TLS, concurrency
│   ├── validators.py     # URL validation & normalization (pure, no I/O)
│   ├── headers.py        # security header / cookie / tech-fingerprint analysis
│   └── utils.py          # DNS resolution, timing, logging helpers
├── tests/
│   └── test_scanner.py   # unit tests (network calls mocked)
├── main.py                # CLI entry point
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml
├── README.md
├── FAQ.md
├── LICENSE
└── .gitignore
```

## Running tests

```bash
pip install -r requirements-dev.txt
pytest -v
# or, stdlib only:
python -m unittest discover tests
```

All scanner tests mock `requests` and DNS resolution, so the suite runs fully offline and deterministically — no live targets are hit during CI.

## Roadmap

Planned as this grows beyond a first version:

- [ ] `--dns-records` — MX/TXT/NS lookups via `dnspython`
- [ ] robots.txt / sitemap.xml discovery (still passive — just fetching well-known files)
- [ ] HTML `<meta generator>` and script-tag based tech fingerprinting
- [ ] CSV / HTML report export alongside JSON
- [ ] Rate limiting / backoff controls for large batch scans
- [ ] Optional `--compare` mode to diff two scans of the same target over time
- [ ] GitHub Actions CI workflow (lint + test on push)

## Responsible use

This tool is intended for scanning **domains and systems you own or are explicitly authorized to test** — your own sites, CTF/lab targets, or engagements with written authorization. Running any scanner, however passive, against systems you don't have permission to test can violate laws such as the U.S. Computer Fraud and Abuse Act or the UK Computer Misuse Act, and equivalents elsewhere. See [`FAQ.md`](FAQ.md) for more detail.

## License

[MIT](LICENSE)
