#!/usr/bin/env python3
"""
Extract all unique URLs from SAP YAML BOM files (excluding specified subdirectories)
and check whether each URL is reachable, returning the HTTP status code.

A 404 response means SAP has removed the file from the download portal.
Other non-2xx codes (e.g. 401, 403) are expected for unauthenticated access
and do NOT indicate a broken URL.
"""

import argparse
import concurrent.futures
import json
import os
import re
import sys
from pathlib import Path

import requests
import yaml

# SAP's download portal redirects unauthenticated requests but 404 is
# returned even without auth when a file no longer exists.
HEADERS = {
    "User-Agent": "Mozilla/5.0 (URL-availability-check; non-interactive)",
}

EXPECTED_NO_AUTH = {401, 403, 302, 200}


def find_yaml_files(sap_dir: Path, exclude_dirs: set[str]) -> list[Path]:
    return [
        p for p in sap_dir.rglob("*.yaml")
        if not any(part in exclude_dirs for part in p.parts)
    ]


def extract_urls(yaml_file: Path) -> list[tuple[str, str]]:
    """Return list of (url, relative_source_path) from a YAML file."""
    try:
        with yaml_file.open() as f:
            content = f.read()
    except OSError:
        return []

    # Use regex rather than full YAML parse to tolerate malformed files
    urls = re.findall(r"^\s+url:\s+(https?://\S+)", content, re.MULTILINE)
    rel = str(yaml_file)
    return [(url, rel) for url in urls]


def check_url(url: str, source: str, timeout: int) -> dict:
    try:
        resp = requests.head(
            url,
            headers=HEADERS,
            timeout=timeout,
            allow_redirects=True,
        )
        # Some servers don't support HEAD; fall back to GET with streaming
        if resp.status_code == 405:
            resp = requests.get(
                url,
                headers=HEADERS,
                timeout=timeout,
                allow_redirects=True,
                stream=True,
            )
            resp.close()
        return {"url": url, "source": source, "status": resp.status_code}
    except requests.exceptions.Timeout:
        return {"url": url, "source": source, "error": "timeout"}
    except requests.exceptions.ConnectionError as e:
        return {"url": url, "source": source, "error": f"connection_error: {e}"}
    except requests.exceptions.RequestException as e:
        return {"url": url, "source": source, "error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Check SAP BOM URLs for availability.")
    parser.add_argument("--sap-dir", default="SAP", help="Root SAP directory")
    parser.add_argument("--exclude-dir", action="append", default=[], dest="exclude_dirs",
                        help="Directory names to exclude (repeatable)")
    parser.add_argument("--output", default="url-check-results.json")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--workers", type=int, default=20)
    args = parser.parse_args()

    sap_dir = Path(args.sap_dir)
    exclude_dirs = set(args.exclude_dirs)

    print(f"Scanning YAML files under '{sap_dir}' (excluding: {exclude_dirs or 'none'})")
    yaml_files = find_yaml_files(sap_dir, exclude_dirs)
    print(f"Found {len(yaml_files)} YAML files")

    # Collect URLs, deduplicate while keeping first-seen source file
    seen: dict[str, str] = {}
    for yf in yaml_files:
        for url, source in extract_urls(yf):
            if url not in seen:
                seen[url] = source

    unique_urls = list(seen.items())
    print(f"Found {len(unique_urls)} unique URLs — checking with {args.workers} workers...")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(check_url, url, source, args.timeout): url
            for url, source in unique_urls
        }
        done = 0
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
            done += 1
            if done % 100 == 0 or done == len(unique_urls):
                print(f"  {done}/{len(unique_urls)} checked", flush=True)

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Results written to '{args.output}'")

    not_found = [r for r in results if r.get("status") == 404]
    if not_found:
        print(f"\n{'='*60}")
        print(f"  404 NOT FOUND: {len(not_found)} URL(s)")
        print(f"{'='*60}")
        for r in not_found:
            print(f"  {r['url']}")
            print(f"    source: {r['source']}")
        sys.exit(1)

    print("All URLs responded (no 404s found).")


if __name__ == "__main__":
    main()
