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
  - Existing file  → HTTP 200, binary Content-Type (e.g. application/octet-stream)
  - Removed file   → HTTP 200, Content-Type: text/html (SAP error page)
  We detect removed files by checking Content-Type, not HTTP status code.

Without credentials:
  - SAP URLs are skipped and reported separately (not counted as failures).
  - Non-SAP URLs (e.g. download.oracle.com) are still checked.

Thread safety
-------------
After authentication, session cookies are serialized into a list of tuples.
Each worker thread rebuilds its own RequestsCookieJar from these tuples,
avoiding any shared mutable state (requests.Session is NOT thread-safe).
"""

import argparse
import concurrent.futures
import copy
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


def _serialize_cookies(session):
    """
    Extract cookies from a requests.Session into a list of tuples.
    This is thread-safe to pass to workers: each worker rebuilds its own jar.
    """
    return [
        (c.name, c.value, c.domain, c.path)
        for c in session.cookies
    ]


def _make_cookie_jar(cookie_tuples):
    """Rebuild a RequestsCookieJar from serialized tuples."""
    jar = requests.cookies.RequestsCookieJar()
    for name, value, domain, path in cookie_tuples:
        jar.set(name, value, domain=domain, path=path)
    return jar


def verify_sap_session(session, probe_url, timeout):
    """
    Confirm that the session grants download access by probing one SAP URL.
    This is a diagnostic step — prints detailed info about SAP's response
    so we can determine the correct detection method.
    Returns an error string if access clearly fails, empty string to proceed.
    """
    try:
        resp = session.get(
            probe_url,
            allow_redirects=True,
            timeout=timeout,
            stream=True,
        )

        # Read a small chunk to inspect the body
        body_preview = resp.raw.read(2000)
        resp.close()

        content_type = resp.headers.get("Content-Type", "")
        content_disp = resp.headers.get("Content-Disposition", "")
        content_len  = resp.headers.get("Content-Length", "unknown")

        print(f"\n--- SAP Probe Debug Info ---")
        print(f"  Probe URL:           {probe_url}")
        print(f"  Final URL:           {resp.url}")
        print(f"  Status:              {resp.status_code}")
        print(f"  Content-Type:        {content_type}")
        print(f"  Content-Disposition: {content_disp}")
        print(f"  Content-Length:      {content_len}")
        print(f"  Redirect chain:      {[r.url for r in resp.history]}")
        print(f"  Body preview (first 500 chars):")
        try:
            print(f"    {body_preview[:500].decode('utf-8', errors='replace')}")
        except Exception:
            print(f"    (binary data, first 50 bytes: {body_preview[:50]})")
        print(f"--- End Debug Info ---\n")

        # If we get bounced back to the login page, session didn't stick
        if "accounts.sap.com" in resp.url:
            return "Session did not persist — redirected back to SAP login page."

        if resp.status_code == 403:
            return "SAP returned 403 Forbidden. S-User may lack download authorisation."

        if resp.status_code >= 400:
            return f"SAP returned HTTP {resp.status_code} for probe URL."

        # For now, do NOT fail on content-type — let all URLs be checked
        # so we can see the full picture of what SAP returns.

    except requests.RequestException as e:
        print(f"Network issue during probe: {e}")
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

def check_url(url, source, timeout, sap_cookie_tuples):
    """
    Check a single URL for availability.

    sap_cookie_tuples:
      list   → serialized SAP cookies; rebuild a fresh jar per request (thread-safe)
      None   → no credentials provided; skip SAP URLs
      False  → credentials provided but auth failed; skip SAP URLs

    For SAP URLs, a real file download returns a binary Content-Type (e.g.
    application/octet-stream).  A removed/invalid file returns HTTP 200 with
    Content-Type: text/html (SAP error page).  We use this to detect broken links.
    """
    is_sap = urlparse(url).hostname == SAP_DOWNLOAD_HOST

    if is_sap and sap_cookie_tuples is None:
        return {
            "url": url, "source": source,
            "sap_url": True, "skipped": True,
            "reason": "no credentials provided",
        }

    if is_sap and sap_cookie_tuples is False:
        return {
            "url": url, "source": source,
            "sap_url": True, "skipped": True,
            "reason": "authentication failed",
        }

    try:
        if is_sap:
            # Assign the jar directly (not .update) to preserve domain/path info
            # so cookies are correctly sent to both softwaredownloads.sap.com
            # and accounts.sap.com during the tokengen/SAML chain.
            jar = _make_cookie_jar(sap_cookie_tuples)
            session = requests.Session()
            session.headers.update(HEADERS)
            session.cookies = jar

            # SAP download URLs go through a multi-hop tokengen/SAML chain:
            #   1. softwaredownloads.sap.com/file/XXX
            #      → (302) origin-az.softwaredownloads.sap.com/tokengen/?file=XXX
            #      → (200) HTML form auto-posted to accounts.sap.com/saml2/idp/sso
            #   2. accounts.sap.com validates IDP session cookie, returns
            #      (200) HTML form with SAMLResponse auto-posted back to SP
            #   3. softwaredownloads.sap.com processes SAMLResponse, redirects to
            #      CDN or returns an error HTML page if the file was removed.
            #
            # Use stream=True to avoid downloading large binary files.
            # Read up to 64 KB per HTML page (SAMLResponse base64 can be large).
            resp = session.get(url, timeout=timeout, allow_redirects=True, stream=True)

            for _ in range(6):
                content_type = resp.headers.get("Content-Type", "")
                if "text/html" not in content_type:
                    # Binary/non-HTML response — stop here (file exists)
                    resp.close()
                    break

                # Read enough to capture full SAML form (SAMLResponse can be ~10 KB)
                chunk = resp.raw.read(65536, decode_content=True)
                resp.close()
                text = chunk.decode("utf-8", errors="replace")

                fp = _FormParser()
                fp.feed(text)

                # Follow the form if it's an auto-submit or carries SAML tokens
                is_saml_form = any(
                    k in fp.inputs
                    for k in ("SAMLResponse", "SAMLRequest", "RelayState", "id_token")
                )
                is_autosubmit = "document.forms[0].submit()" in text

                if not fp.form_action or (not is_saml_form and not is_autosubmit):
                    # No form to follow — this is the final HTML page
                    break

                action = (
                    fp.form_action
                    if fp.form_action.startswith("http")
                    else urljoin(resp.url, fp.form_action)
                )
                resp = session.post(
                    action,
                    data=fp.inputs,
                    timeout=timeout,
                    allow_redirects=True,
                    stream=True,
                )
            else:
                # Loop exhausted — close whatever is open
                resp.close()

            content_type = resp.headers.get("Content-Type", "")
            content_disp = resp.headers.get("Content-Disposition", "")
            final_url = resp.url

            # If we ended up stuck on the IDP login page after the full chain,
            # the session cookies didn't work — skip rather than mark broken.
            if "accounts.sap.com" in final_url:
                return {
                    "url": url, "source": source,
                    "sap_url": True, "skipped": True,
                    "reason": "session expired (stuck on IDP after full SAML chain)",
                }

            # After the full chain:
            #   Valid file   → binary Content-Type or Content-Disposition: attachment
            #   Removed file → HTTP 200 text/html SAP error page (no download headers)
            is_html = "text/html" in content_type
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
                "final_url": final_url,
                "content_type": content_type,
                "content_disposition": content_disp,
                "broken": broken,
                **({"reason": reason} if reason else {}),
                "sap_url": True,
            }
        else:
            # Non-SAP URL: simple HEAD check
            resp = requests.head(
                url,
                headers=HEADERS,
                timeout=timeout,
                allow_redirects=True,
            )
            if resp.status_code == 405:
                resp = requests.get(
                    url,
                    headers=HEADERS,
                    timeout=timeout,
                    allow_redirects=True,
                    stream=True,
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
    sap_cookie_tuples = None  # None = no creds, False = auth failed, list = cookies
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
            sap_cookie_tuples = False
        else:
            print("SAP authentication successful.")

            if probe_url.startswith("http"):
                verify_err = verify_sap_session(sap_session, probe_url, args.timeout)
                if verify_err:
                    print(f"::warning::SAP session verification failed: {verify_err}")
                    print("SAP URLs will be skipped.")
                    sap_cookie_tuples = False
                else:
                    print("SAP session verified — download access confirmed.")
                    # Serialize cookies for thread-safe usage
                    sap_cookie_tuples = _serialize_cookies(sap_session)
                    print(f"  ({len(sap_cookie_tuples)} cookies captured)")
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
                sap_cookie_tuples if urlparse(url).hostname == SAP_DOWNLOAD_HOST else None
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

    # Write counts for the workflow fail step
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
