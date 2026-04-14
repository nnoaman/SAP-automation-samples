#!/usr/bin/env python3
"""
Extract all unique URLs from SAP YAML BOM files and check their availability.

SAP Authentication
------------------
SAP Software Downloads (softwaredownloads.sap.com) supports HTTP Basic Auth
directly on the download endpoint — the same mechanism used by the Ansible
BOM downloader playbook (ansible.builtin.get_url with url_username/url_password
and force_basic_auth=true, http_agent='SAP Software Download').

Set S_USERNAME and S_PASSWORD environment variables (S-User ID + password).
With credentials:
  - Existing file  → HTTP 200, binary Content-Type or Content-Disposition: attachment
  - Removed file   → HTTP 200, Content-Type: text/html (SAP error page)

Without credentials:
  - SAP URLs are skipped and reported separately (not counted as failures).
  - Non-SAP URLs (e.g. download.oracle.com) are still checked.
"""

import argparse
import concurrent.futures
import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse

import requests

SAP_DOWNLOAD_HOST = "softwaredownloads.sap.com"
SAP_HTTP_AGENT    = "SAP Software Download"
HEADERS = {"User-Agent": SAP_HTTP_AGENT}


class _ForceBasicAuthSession(requests.Session):
    """
    Mirrors Ansible get_url's force_basic_auth=true behaviour:
    the Authorization: Basic header is sent on every request including
    all redirected hops, regardless of hostname changes.
    requests.Session normally strips auth when redirecting cross-domain.
    """
    def rebuild_auth(self, prepared_request, response):
        pass  # never strip auth


class _ForceBasicAuthSession(requests.Session):
    """
    Mirrors Ansible get_url's force_basic_auth=true behaviour:
    the Authorization: Basic header is sent on every request including
    all redirected hops, regardless of hostname changes.
    requests.Session normally strips auth when redirecting cross-domain.
    """
    def rebuild_auth(self, prepared_request, response):
        pass  # never strip auth


def find_yaml_files(sap_dir, exclude_dirs):
    return [
        p for p in sap_dir.rglob("*.yaml")
        if not any(part in exclude_dirs for part in p.parts)
    ]


def extract_urls(yaml_file):
    try:
        content = yaml_file.read_text()
    except OSError:
        return []
    urls = re.findall(r"^\s+url:\s+(https?://\S+)", content, re.MULTILINE)
    return [(url, str(yaml_file)) for url in urls]


def check_url(url, source, timeout, sap_user, sap_password):
    """
    Check a single URL for availability.

    SAP URLs: HTTP Basic Auth sent preemptively (force_basic_auth style).
      Valid file   → binary Content-Type or Content-Disposition: attachment
      Removed file → text/html, no attachment header
    Non-SAP URLs: simple HEAD request.
    """
    is_sap = urlparse(url).hostname == SAP_DOWNLOAD_HOST

    if is_sap and not sap_user:
        return {
            "url": url, "source": source,
            "sap_url": True, "skipped": True,
            "reason": "no credentials provided",
        }

    try:
        if is_sap:
            resp = _ForceBasicAuthSession().request(
                "GET",
                url,
                auth=(sap_user, sap_password),
                headers=HEADERS,
                timeout=timeout,
                allow_redirects=True,
                stream=True,
            )
            resp.raw.read(256, decode_content=True)
            resp.close()

            content_type = resp.headers.get("Content-Type", "")
            content_disp = resp.headers.get("Content-Disposition", "")
            is_html      = "text/html" in content_type
            has_download = "attachment" in content_disp or not is_html
            broken = resp.status_code >= 400 or (is_html and not has_download)
            reason = None
            if resp.status_code >= 400:
                reason = f"HTTP {resp.status_code}"
            elif is_html and not has_download:
                reason = "SAP returned HTML (file likely removed or unauthorised)"

            return {
                "url": url, "source": source,
                "status": resp.status_code,
                "final_url": resp.url,
                "content_type": content_type,
                "content_disposition": content_disp,
                "broken": broken,
                **({"reason": reason} if reason else {}),
                "sap_url": True,
            }
        else:
            resp = requests.head(
                url, headers=HEADERS, timeout=timeout, allow_redirects=True,
            )
            if resp.status_code == 405:
                resp = requests.get(
                    url, headers=HEADERS, timeout=timeout,
                    allow_redirects=True, stream=True,
                )
                resp.close()
            broken = resp.status_code == 404
            return {
                "url": url, "source": source,
                "status": resp.status_code,
                "broken": broken,
                "sap_url": False,
            }

    except requests.exceptions.Timeout:
        return {"url": url, "source": source, "error": "timeout",
                "broken": True, "sap_url": is_sap}
    except requests.exceptions.ConnectionError as e:
        return {"url": url, "source": source, "error": f"connection_error: {e}",
                "broken": True, "sap_url": is_sap}
    except requests.exceptions.RequestException as e:
        return {"url": url, "source": source, "error": str(e),
                "broken": True, "sap_url": is_sap}


def main():
    parser = argparse.ArgumentParser(description="Check SAP BOM URLs for availability.")
    parser.add_argument("--sap-dir",      default="SAP")
    parser.add_argument("--exclude-dir",  action="append", default=[], dest="exclude_dirs")
    parser.add_argument("--output",       default="url-check-results.json")
    parser.add_argument("--timeout",      type=int, default=30)
    parser.add_argument("--workers",      type=int, default=20)
    parser.add_argument("--sap-user",     default=os.environ.get("S_USERNAME", ""))
    parser.add_argument("--sap-password", default=os.environ.get("S_PASSWORD", ""))
    args = parser.parse_args()

    sap_dir      = Path(args.sap_dir)
    exclude_dirs = set(args.exclude_dirs)

    with open(args.output, "w") as f:
        json.dump([], f)

    print(f"\nScanning YAML files under '{sap_dir}' (excluding: {exclude_dirs or 'none'})")
    yaml_files = find_yaml_files(sap_dir, exclude_dirs)
    print(f"Found {len(yaml_files)} YAML files")

    seen = {}
    for yf in yaml_files:
        for url, source in extract_urls(yf):
            if url not in seen:
                seen[url] = source

    unique_urls = list(seen.items())
    sap_count   = sum(1 for u, _ in unique_urls if urlparse(u).hostname == SAP_DOWNLOAD_HOST)
    other_count = len(unique_urls) - sap_count
    print(f"Found {len(unique_urls)} unique URLs "
          f"({sap_count} SAP, {other_count} non-SAP) — "
          f"checking with {args.workers} workers...")

    if args.sap_user:
        print(f"SAP credentials provided — SAP URLs will be checked.")
        if sap_count > 0:
            probe_url = next(u for u, _ in unique_urls if urlparse(u).hostname == SAP_DOWNLOAD_HOST)
            print(f"\nProbing SAP auth with: {probe_url}")
            probe = check_url(probe_url, "probe", args.timeout, args.sap_user, args.sap_password)
            print(f"  status={probe.get('status')}  content_type={probe.get('content_type')}  "
                  f"broken={probe.get('broken')}  reason={probe.get('reason', '-')}")
            print()
    else:
        print("No SAP credentials provided (set S_USERNAME / S_PASSWORD).")
        print("SAP URLs will be skipped; only non-SAP URLs will be checked.")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                check_url, url, source, args.timeout,
                args.sap_user if urlparse(url).hostname == SAP_DOWNLOAD_HOST else "",
                args.sap_password,
            ): url
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

    skipped    = [r for r in results if r.get("skipped")]
    broken     = [r for r in results if r.get("broken")]
    not_found  = [r for r in broken if r.get("status") == 404]
    html_pages = [r for r in broken if "html" in r.get("reason", "").lower() and r.get("sap_url")]
    errors     = [r for r in broken if "error" in r]

    print(f"\n{'='*60}")
    print(f"  Checked : {len(results) - len(skipped)}")
    print(f"  Skipped : {len(skipped)}")
    print(f"  Broken  : {len(broken)}")
    print(f"    404s            : {len(not_found)}")
    print(f"    SAP HTML pages  : {len(html_pages)}  (file likely removed)")
    print(f"    Conn errors     : {len(errors)}")
    print(f"{'='*60}")

    if html_pages:
        print(f"\nSAP FILES LIKELY REMOVED ({len(html_pages)}):")
        for r in html_pages:
            print(f"  {r['url']}\n    source: {r['source']}")

    if not_found:
        print(f"\n404 NOT FOUND ({len(not_found)}):")
        for r in not_found:
            print(f"  {r['url']}\n    source: {r['source']}")

    if errors:
        print(f"\nConnection errors ({len(errors)}):")
        for r in errors[:50]:
            print(f"  {r['url']}  ({r['error']})\n    source: {r['source']}")

    if skipped:
        print(f"\nSkipped {len(skipped)} SAP URL(s) — set S_USERNAME and S_PASSWORD to check them.")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"broken_count={len(broken)}\n")
            f.write(f"not_found_count={len(not_found)}\n")
            f.write(f"html_page_count={len(html_pages)}\n")
            f.write(f"error_count={len(errors)}\n")
            f.write(f"skipped_count={len(skipped)}\n")

    print(f"\nDone. Full results written to '{args.output}'")


if __name__ == "__main__":
    main()
