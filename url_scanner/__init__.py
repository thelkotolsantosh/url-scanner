"""
url-scanner
===========

A passive, non-destructive URL / website reconnaissance tool.

Checks performed:
    - URL validation & normalization
    - DNS resolution
    - HTTP status & redirect chain
    - TLS/SSL certificate inspection
    - HTTP response header analysis (security headers)
    - Cookie flag analysis (Secure / HttpOnly / SameSite)
    - Lightweight technology fingerprinting

This tool never attempts exploitation, brute forcing, fuzzing, or any
active attack against a target. It only inspects information a normal
browser request would already reveal.
"""

__title__ = "url-scanner"
__version__ = "0.1.0"
__author__ = "your-name-here"
__license__ = "MIT"

from .scanner import scan_url, scan_many  # noqa: F401
from .validators import validate_url, normalize_url  # noqa: F401

__all__ = [
    "scan_url",
    "scan_many",
    "validate_url",
    "normalize_url",
    "__version__",
]
