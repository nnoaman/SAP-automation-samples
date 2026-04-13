#!/usr/bin/env python3
"""
Extract all unique URLs from SAP YAML BOM files and check their availability.

SAP Authentication
------------------
SAP Software Downloads (softwaredownloads.sap.com) uses OAuth via accounts.sap.com.
Without authentication, EVERY URL — valid or missing — returns HTTP 302 → 200
(SAP redirects all unauthenticated requests to its login/token page), so it is
impossible to distinguish a live file from a removed one without credentials.

Set SAP_USERNAME and SAP_PASSWORD environment variables (S-User ID + password).
With credentials:
  - Existing file  → HTTP 200
  - Removed file   → HTTP 404

Without credentials:
  - SAP URLs are skipped and reported separately (not counted as failures).
  - Non-SAP URLs (e.g. download.oracle.com) are still checked.

Thread safety
-------------
The authenticated SAP session cookies are extracted once after login and
injected into each per-thread request — the Session object itself is not
shared across threads.
"""

import argparse
import concurrent.futures
import json
import os
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

SAP_DOWNLOAD_HOST = "softwaredownloads.sap.com"


# ---------------------------------------------------------------------------
# HTML form parser (used to extract SAP login form fields)
# ---------------------------------------------------------------------------

class _FormParser(HTMLParser):
    """Extract the first <form> action and all <input> fields within it."""

    def __init__(self):
        super().__init__()
        self.form_action: str = ""
        self.inputs: dict = {}
        self.in_first_form = False
        self.found_form = False

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "form" and not self.found_form:
            self.form_action = d.get("action", "")
            self.in_first_form = True
            self.found_form = True
        elif tag == "input" and self.in_first_form:
            name = d.get("name", "")
            if name:
                self.inputs[name] = d.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form" and self.in_first_form:
            self.in_first_form = False


# ---------------------------------------------------------------------------
# SAP authentication
# ---------------------------------------------------------------------------

def create_sap_session(username, password, probe_url, timeout):
    """
    Authenticate with SAP accounts.sap.com via form-based OAuth.

    Returns (requests.Session, error_str).
    session is None on failure; error_str is empty on success.
    """
    session = requests.Session()
    session.headers.update(HEADERS)

    # 1. Trigger the OAuth redirect by hitting an actual download URL
    #    (Using a real file URL ensures the SSO RelayState is set up for file downloads,
    #     whereas index.jsp might not grant the correct entitlement scopes).
    try:
        resp = session.get(
            probe_url or "https://softwaredownloads.sap.com/index.jsp",
            allow_redirects=True,
            timeout=timeout,
        )
    except requests.RequestException as e:
        return None, f"Could not reach SAP portal: {e}"

    if "accounts.sap.com" not in resp.url:
        # Unexpected — return the session as-is
        return session, ""

    # 2. Parse the login form
    fp = _FormParser()
    fp.feed(resp.text)

    if not fp.form_action:
        return None, (
            "Login form not found on SAP accounts page. "
            "SAP may have changed their OAuth flow."
        )

    action = (
        fp.form_action
        if fp.form_action.startswith("http")
        else urljoin(resp.url, fp.form_action)
    )

    # 3. Submit credentials — SAP uses j_username / j_password field names
    login_data = {**fp.inputs, "j_username": username, "j_password": password}
    try:
        login_resp = session.post(
            action,
            data=login_data,
            allow_redirects=True,
            timeout=timeout,
        )
    except requests.RequestException as e:
        return None, f"Login POST failed: {e}"

    # SAP frequently uses an auto-submitting HTML form (SAML or OpenID Connect)
    # to pass the authentication token back to softwaredownloads.sap.com.
    # We must follow these SSO redirects manually since requests doesn't run JS.
    for _ in range(5):
        sso_fp = _FormParser()
        sso_fp.feed(login_resp.text)

        is_sso_form = any(
            k in sso_fp.inputs
            for k in ("SAMLResponse", "SAMLRequest", "code", "RelayState", "id_token")
        )
        if sso_fp.form_action and is_sso_form:
            next_action = (
                sso_fp.form_action
                if sso_fp.form_action.startswith("http")
                else urljoin(login_resp.url, sso_fp.form_action)
            )
            try:
                login_resp = session.post(
                    next_action,
                    data=sso_fp.inputs,
                    allow_redirects=True,
                    timeout=timeout,
                )
            except requests.RequestException as e:
                return None, f"SSO POST failed: {e}"
        else:
            break

    # 4. Verify: if still on the login page, credentials were rejected
    check_fp = _FormParser()
    check_fp.feed(login_resp.text)
    if "j_password" in check_fp.inputs or "j_username" in check_fp.inputs:
        return None, "SAP rejected credentials (login form reappeared)"

    # Return the raw RequestsCookieJar to preserve all cookie domains/paths.
    # get_dict() strips cross-domain info, breaking redirects to tokengen subdomains.
    return session, ""


def verify_sap_session(session, probe_url, timeout):
    """
    Confirm that the session actually grants download access by probing one SAP URL.
    Returns an error string if it doesn't, empty string if it does.
    """
    try:
        resp = session.get(
            probe_url,
            allow_redirects=True,
            timeout=timeout,
        )
        if "tokengen" in resp.url:
            return (
                f"Session cookies do not grant download access — "
                f"SAP file requests still redirect to tokengen/ "
                f"(Final URL: {resp.url}). "
                f"Check that the S-User has Software Download authorisation."
            )
    except requests.RequestException as e:
        print(f"Network issue during probe: {e}")
        pass  # Network issue on probe — proceed optimistically
    return ""


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# URL checker
# ---------------------------------------------------------------------------

def check_url(url, source, timeout, sap_session):
    """
    sap_session:
      requests.Session() → authenticated SAP session; use it for SAP URLs
      None  → no credentials provided; skip SAP URLs
      False → credentials provided but authentication/verification failed; skip SAP URLs
    """
    is_sap = urlparse(url).hostname == SAP_DOWNLOAD_HOST

    if is_sap and sap_session is None:
        return {
            "url": url, "source": source,
            "sap_url": True, "skipped": True,
            "reason": "no credentials provided",
        }

    if is_sap and sap_session is False:
        return {
            "url": url, "source": source,
            "sap_url": True, "skipped": True,
            "reason": "authentication failed",
        }

    req_session = sap_session if is_sap else requests
    headers = None if is_sap else HEADERS

    try:
        resp = req_session.head(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
        )
        # Some servers reject HEAD; fall back to streaming GET
        if resp.status_code == 405:
            resp = req_session.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
                stream=True,
            )
            resp.close()

        # If the final URL contains tokengen/, our session cookies did not grant
        # real download access — the result is unreliable (not a real 200/404).
        if is_sap and "tokengen" in resp.url:
            return {
                "url": url, "source": source,
                "sap_url": True, "skipped": True,
                "reason": "unauthenticated (tokengen redirect — cookies not effective)",
            }

        broken = resp.status_code == 404
        return {
            "url": url, "source": source,
            "status": resp.status_code,
            "broken": broken,
            "sap_url": is_sap,
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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Check SAP BOM URLs for availability.")
    parser.add_argument("--sap-dir", default="SAP")
    parser.add_argument("--exclude-dir", action="append", default=[], dest="exclude_dirs")
    parser.add_argument("--output", default="url-check-results.json")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--workers", type=int, default=20)
    # Credentials: CLI args take priority, then environment variables
    parser.add_argument("--sap-user",     default=os.environ.get("S_USERNAME", ""))
    parser.add_argument("--sap-password", default=os.environ.get("S_PASSWORD", ""))
    args = parser.parse_args()

    sap_dir      = Path(args.sap_dir)
    exclude_dirs = set(args.exclude_dirs)

    # Write empty results immediately so the summary step always finds the file
    # even if this script crashes before completing.
    with open(args.output, "w") as f:
        json.dump([], f)

    # -- Scan YAML files first (probe URL comes from real data) -----------
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

    # -- Authenticate with SAP ------------------------------------------
    sap_session = None
    if args.sap_user and args.sap_password:
        print("Authenticating with SAP...")
        # Get one real URL to trigger the SSO flow properly
        probe_url = next(
            (u for u, _ in unique_urls if urlparse(u).hostname == SAP_DOWNLOAD_HOST),
            "https://softwaredownloads.sap.com/index.jsp",
        )

        sap_session, auth_err = create_sap_session(
            args.sap_user, args.sap_password, probe_url, args.timeout
        )
        if auth_err:
            print(f"::warning::SAP authentication failed: {auth_err}")
            print("SAP URLs will be skipped.")
            sap_session = False  # credentials present but auth failed
        else:
            print("SAP authentication successful.")

            if probe_url.startswith("http"):
                verify_err = verify_sap_session(sap_session, probe_url, args.timeout)
                if verify_err:
                    print(f"::warning::SAP session verification failed: {verify_err}")
                    print("SAP URLs will be skipped.")
                    sap_session = False  # credentials present but session not effective
                else:
                    print("SAP session verified — download access confirmed.")
            else:
                print("No SAP URLs found to probe; skipping session verification.")
    else:
        print("No SAP credentials provided (set S_USERNAME / S_PASSWORD).")
        print("SAP URLs will be skipped; only non-SAP URLs will be checked.")

    # -- Check URLs -----------------------------------------------------
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                check_url, url, source, args.timeout,
                # Pass real session for SAP URLs, None for non-SAP
                sap_session if urlparse(url).hostname == SAP_DOWNLOAD_HOST else None
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

    # -- Report ---------------------------------------------------------
    skipped   = [r for r in results if r.get("skipped")]
    broken    = [r for r in results if r.get("broken")]
    not_found = [r for r in broken if r.get("status") == 404]
    errors    = [r for r in broken if "error" in r]

    print(f"\n{'='*60}")
    print(f"  Checked : {len(results) - len(skipped)}")
    print(f"  Skipped : {len(skipped)}  (SAP URLs — no credentials)")
    print(f"  404s    : {len(not_found)}")
    print(f"  Errors  : {len(errors)}")
    print(f"{'='*60}")

    if not_found:
        print(f"\n404 NOT FOUND:")
        for r in not_found:
            print(f"  {r['url']}\n    source: {r['source']}")

    if errors:
        print(f"\nConnection errors:")
        for r in errors:
            print(f"  {r['url']}  ({r['error']})\n    source: {r['source']}")

    if skipped:
        print(f"\nSkipped {len(skipped)} SAP URL(s) — set S_USERNAME and S_PASSWORD to check them.")

    # Write counts for the workflow fail step
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"not_found_count={len(not_found)}\n")
            f.write(f"error_count={len(errors)}\n")
            f.write(f"skipped_count={len(skipped)}\n")

    print(f"\nDone. Full results written to '{args.output}'")


if __name__ == "__main__":
    main()
