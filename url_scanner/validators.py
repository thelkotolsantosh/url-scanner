"""
validators.py
==============

Pure, network-free functions for validating and normalizing URLs.

Kept dependency-free (stdlib only) so it can be unit tested in
isolation without mocking any network calls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

# A pragmatic hostname/domain pattern: labels of letters/digits/hyphens,
# separated by dots, with a final TLD label of at least 2 letters.
# Also allows raw IPv4 addresses and localhost.
_DOMAIN_RE = re.compile(
    r"^(("
    r"([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}"
    r")|localhost|"
    r"(\d{1,3}\.){3}\d{1,3}"
    r")$"
)

ALLOWED_SCHEMES = ("http", "https")


class InvalidURLError(ValueError):
    """Raised when a URL fails validation."""


@dataclass
class ParsedTarget:
    original: str
    normalized: str
    scheme: str
    hostname: str
    port: int | None
    path: str


def normalize_url(url: str) -> str:
    """
    Normalize a user-supplied URL string.

    - Strips surrounding whitespace.
    - Adds an ``https://`` scheme if none was supplied.
    - Lowercases the scheme and hostname.
    - Leaves path/query/fragment untouched (case can be significant there).
    """
    url = url.strip()
    if not url:
        raise InvalidURLError("Empty URL.")

    # If there's no scheme at all (e.g. "example.com" or "example.com/a"),
    # prepend https:// before parsing so urlparse treats it correctly.
    if "://" not in url:
        url = f"https://{url}"

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        raise InvalidURLError(f"Could not determine hostname from: {url!r}")

    netloc = hostname
    if parsed.port:
        netloc = f"{hostname}:{parsed.port}"
    if parsed.username:
        # Credentials in URLs are unusual for this tool's use case;
        # reject rather than silently dropping them.
        raise InvalidURLError("URLs containing credentials are not supported.")

    normalized = urlunparse(
        (scheme, netloc, parsed.path or "", parsed.params, parsed.query, "")
    )
    return normalized


def validate_url(url: str) -> ParsedTarget:
    """
    Validate a URL and return a :class:`ParsedTarget`.

    Raises :class:`InvalidURLError` with a human-readable reason on
    failure. Does not perform any network I/O.
    """
    normalized = normalize_url(url)
    parsed = urlparse(normalized)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise InvalidURLError(
            f"Unsupported scheme '{parsed.scheme}'. Only http/https are allowed."
        )

    hostname = parsed.hostname or ""
    if not _DOMAIN_RE.match(hostname):
        raise InvalidURLError(f"'{hostname}' does not look like a valid hostname.")

    return ParsedTarget(
        original=url,
        normalized=normalized,
        scheme=parsed.scheme,
        hostname=hostname,
        port=parsed.port,
        path=parsed.path or "/",
    )


def is_probably_url(text: str) -> bool:
    """
    Best-effort, forgiving check for "does this look like a URL" —
    used by main.py to decide whether a CLI argument is a single
    target or the path to a file containing a list of targets.
    """
    try:
        validate_url(text)
        return True
    except InvalidURLError:
        return False
