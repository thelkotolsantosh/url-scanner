"""
utils.py
========

Small, focused helpers shared across the scanner: DNS resolution,
timing, logging setup, and console-friendly formatting. Kept stdlib
only so the tool has minimal external dependencies.
"""

from __future__ import annotations

import logging
import socket
import time
from contextlib import contextmanager
from typing import Iterator


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure and return the package logger."""
    logger = logging.getLogger("url_scanner")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
        )
        logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose else logging.WARNING)
    return logger


@contextmanager
def timer() -> Iterator[dict]:
    """
    Context manager that measures elapsed wall-clock time.

    Usage:
        with timer() as t:
            do_work()
        print(t["elapsed_ms"])
    """
    result = {"elapsed_ms": None}
    start = time.perf_counter()
    try:
        yield result
    finally:
        result["elapsed_ms"] = round((time.perf_counter() - start) * 1000, 2)


def resolve_dns(hostname: str, timeout: float = 5.0) -> dict:
    """
    Resolve a hostname to its IPv4/IPv6 addresses.

    Returns a dict:
        {
            "hostname": str,
            "resolved": bool,
            "addresses": [str, ...],
            "error": str | None,
            "resolution_time_ms": float,
        }

    Uses socket.getaddrinfo (stdlib) rather than requiring dnspython,
    to keep the base install dependency-free. This gives A/AAAA
    results but not raw record types like MX/TXT/NS.
    """
    socket.setdefaulttimeout(timeout)
    result = {
        "hostname": hostname,
        "resolved": False,
        "addresses": [],
        "error": None,
        "resolution_time_ms": None,
    }
    start = time.perf_counter()
    try:
        infos = socket.getaddrinfo(hostname, None)
        addresses = sorted({info[4][0] for info in infos})
        result["addresses"] = addresses
        result["resolved"] = len(addresses) > 0
    except socket.gaierror as exc:
        result["error"] = str(exc)
    except socket.timeout:
        result["error"] = "DNS resolution timed out"
    finally:
        result["resolution_time_ms"] = round((time.perf_counter() - start) * 1000, 2)
        socket.setdefaulttimeout(None)
    return result


def truncate(text: str, length: int = 80) -> str:
    """Truncate long strings for compact console output."""
    if text is None:
        return ""
    text = str(text)
    return text if len(text) <= length else text[: length - 1] + "…"


def human_bool(value: bool) -> str:
    """Render a boolean as a check/cross for console output."""
    return "✔" if value else "✘"
