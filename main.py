"""Inspect a URL and print its scan result as JSON."""

import argparse
import json

from url_scanner import scan_many, scan_url


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("url", nargs="?")
    group.add_argument("--file", help="Text file containing one URL per line")
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("timeout must be greater than zero")
    try:
        if args.file:
            with open(args.file, encoding="utf-8") as handle:
                result = scan_many([line.strip() for line in handle if line.strip()], timeout=args.timeout)
        else:
            result = scan_url(args.url, timeout=args.timeout)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Error: {error}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
