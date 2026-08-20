"""
scanner.py
==========

Orchestrates a passive scan of a single URL:

    1. Validate & normalize the URL           (validators.py)
    2. Resolve DNS                            (utils.py)
    3. Make an HTTP GET request, follow redirects, record the chain
    4. Inspect the TLS certificate (https:// targets only)
    5. Analyze security headers & cookies     (headers.py)
    6. Produce lightweight technology hints   (headers.py)

Nothing here sends anything other than a standard GET request with a
descriptive User-Agent. No fuzzing, no auth brute-forcing, no payload
injection — this is reconnaissance, not exploitation.
"""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import socket
import ssl
from typing import Any, Iterable

import requests

from . import headers as headers_mod
from . import utils
from .validators import InvalidURLError, validate_url

DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "url-scanner/0.1 (+passive recon; https://github.com/)"

logger = utils.setup_logging()


def scan_url(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
    check_tls: bool = True,
) -> dict[str, Any]:
    """
    Run a full passive scan against a single URL and return a
    JSON-serializable dict of findings. Never raises for
    scan-target problems (bad DNS, connection refused, TLS errors,
    etc.) — those are captured under result["errors"] instead. It
    only raises for a malformed *input* (InvalidURLError propagates
    so callers can distinguish "bad input" from "target unreachable").
    """
    target = validate_url(url)  # raises InvalidURLError on bad input

    result: dict[str, Any] = {
        "input": url,
        "normalized_url": target.normalized,
        "hostname": target.hostname,
        "scheme": target.scheme,
        "scanned_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "dns": None,
        "http": None,
        "tls": None,
        "security_headers": None,
        "cookies": None,
        "technology": [],
        "errors": [],
    }

    # 1. DNS
    dns_result = utils.resolve_dns(target.hostname, timeout=timeout)
    result["dns"] = dns_result
    if not dns_result["resolved"]:
        result["errors"].append(f"DNS resolution failed: {dns_result['error']}")
        return result  # nothing else is reachable without DNS

    # 2. HTTP
    http_result, response = _perform_http_get(
        target.normalized, timeout=timeout, user_agent=user_agent
    )
    result["http"] = http_result
    if response is None:
        result["errors"].append(http_result.get("error", "HTTP request failed"))
        return result

    # 3. TLS (only meaningful for https, and only if the connection succeeded)
    if check_tls and target.scheme == "https":
        result["tls"] = _inspect_tls_certificate(target.hostname, timeout=timeout)
        if result["tls"].get("error"):
            result["errors"].append(f"TLS inspection: {result['tls']['error']}")

    # 4. Headers + cookies + tech fingerprint
    result["security_headers"] = headers_mod.analyze_headers(response.headers)

    set_cookie_headers = response.raw.headers.get_all("Set-Cookie") or []
    # requests' urllib3 raw headers support get_all; fall back gracefully
    if not set_cookie_headers and "Set-Cookie" in response.headers:
        set_cookie_headers = [response.headers["Set-Cookie"]]
    result["cookies"] = headers_mod.analyze_cookies(set_cookie_headers)

    result["technology"] = headers_mod.fingerprint_technology(
        response.headers, result["cookies"]
    )

    return result


def scan_many(
    urls: Iterable[str],
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = 5,
    check_tls: bool = True,
) -> list[dict[str, Any]]:
    """
    Scan multiple URLs concurrently using a thread pool (I/O-bound
    workload, so threads are appropriate here rather than
    multiprocessing). Preserves the input order in the returned list.
    """
    urls = list(urls)
    results: list[dict[str, Any] | None] = [None] * len(urls)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_index = {
            pool.submit(_scan_url_safe, url, timeout, check_tls): i
            for i, url in enumerate(urls)
        }
        for future in concurrent.futures.as_completed(future_to_index):
            index = future_to_index[future]
            results[index] = future.result()

    return results  # type: ignore[return-value]


def _scan_url_safe(url: str, timeout: float, check_tls: bool) -> dict[str, Any]:
    """Wrap scan_url so a single bad input doesn't kill the whole batch."""
    try:
        return scan_url(url, timeout=timeout, check_tls=check_tls)
    except InvalidURLError as exc:
        return {
            "input": url,
            "normalized_url": None,
            "hostname": None,
            "scheme": None,
            "dns": None,
            "http": None,
            "tls": None,
            "security_headers": None,
            "cookies": None,
            "technology": [],
            "errors": [f"Invalid URL: {exc}"],
        }


def _perform_http_get(
    url: str, timeout: float, user_agent: str
) -> tuple[dict[str, Any], requests.Response | None]:
    """Issue the GET request and build the 'http' section of the result."""
    http_result: dict[str, Any] = {
        "status_code": None,
        "final_url": None,
        "redirect_chain": [],
        "response_time_ms": None,
        "content_type": None,
        "content_length": None,
        "error": None,
    }
    try:
        with utils.timer() as t:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": user_agent},
            )
        http_result["response_time_ms"] = t["elapsed_ms"]
        http_result["status_code"] = response.status_code
        http_result["final_url"] = response.url
        http_result["redirect_chain"] = [
            {"url": r.url, "status_code": r.status_code} for r in response.history
        ]
        http_result["content_type"] = response.headers.get("Content-Type")
        http_result["content_length"] = response.headers.get("Content-Length") or len(
            response.content
        )
        return http_result, response
    except requests.exceptions.SSLError as exc:
        http_result["error"] = f"SSL error: {exc}"
    except requests.exceptions.ConnectionError as exc:
        http_result["error"] = f"Connection error: {exc}"
    except requests.exceptions.Timeout:
        http_result["error"] = f"Request timed out after {timeout}s"
    except requests.exceptions.RequestException as exc:
        http_result["error"] = f"Request failed: {exc}"
    return http_result, None


def _inspect_tls_certificate(hostname: str, timeout: float) -> dict[str, Any]:
    """
    Open a raw TLS connection to inspect the certificate presented by
    the server. This is read-only certificate metadata — the same
    information any browser reads before showing the padlock icon.
    """
    tls_result: dict[str, Any] = {
        "issuer": None,
        "subject": None,
        "not_before": None,
        "not_after": None,
        "days_until_expiry": None,
        "expired": None,
        "protocol_version": None,
        "cipher": None,
        "san": [],
        "error": None,
    }
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_result["protocol_version"] = ssock.version()
                tls_result["cipher"] = cipher[0] if cipher else None

        tls_result["issuer"] = _format_x509_name(cert.get("issuer"))
        tls_result["subject"] = _format_x509_name(cert.get("subject"))
        tls_result["san"] = [
            value for (key, value) in cert.get("subjectAltName", []) if key == "DNS"
        ]

        not_before = _parse_cert_date(cert.get("notBefore"))
        not_after = _parse_cert_date(cert.get("notAfter"))
        tls_result["not_before"] = not_before.isoformat() if not_before else None
        tls_result["not_after"] = not_after.isoformat() if not_after else None
        if not_after:
            delta = not_after - dt.datetime.now(dt.timezone.utc)
            tls_result["days_until_expiry"] = delta.days
            tls_result["expired"] = delta.total_seconds() < 0
    except ssl.SSLCertVerificationError as exc:
        tls_result["error"] = f"Certificate verification failed: {exc}"
    except (socket.timeout, TimeoutError):
        tls_result["error"] = f"TLS connection timed out after {timeout}s"
    except (socket.gaierror, ConnectionRefusedError, OSError) as exc:
        tls_result["error"] = f"Could not establish TLS connection: {exc}"
    return tls_result


def _format_x509_name(name_tuple) -> str | None:
    """Flatten the tuple-of-tuples cert name format into 'CN=..., O=...'."""
    if not name_tuple:
        return None
    parts = []
    for rdn in name_tuple:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _parse_cert_date(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    # Certificate dates look like: 'Jun  1 12:00:00 2026 GMT'
    parsed = dt.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
    return parsed.replace(tzinfo=dt.timezone.utc)
