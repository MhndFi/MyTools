#!/usr/bin/env python3
"""
tumblr-idor-probe.py — Tumblr API IDOR Scanner
================================================
Automates cross-account access testing against Tumblr's private API endpoints.
Compares responses between victim-authenticated and attacker-authenticated requests
to surface Insecure Direct Object Reference vulnerabilities.

Usage:
    python3 tumblr-idor-probe.py \
        --victim-blog  mhndfi-hc \
        --victim-cookie "ACCOUNT1_COOKIES" \
        --attacker-cookie "ACCOUNT2_COOKIES" \
        [--output-html report.html] \
        [--verbose]

Designed for HackerOne Bug Bounty (Automattic — Tumblr program).
Build: Daema / @DaemaAI — Feb 21, 2026
"""

import argparse
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("[!] 'requests' not found. Run: pip3 install requests")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────
# ENDPOINT DEFINITIONS
# Each entry: (label, path_template, method, sensitive_keys)
# {BLOG} is replaced with victim blog name
# sensitive_keys = JSON keys we search for in response body
# ─────────────────────────────────────────────────────────────
ENDPOINTS = [
    # ── Blog-scoped private endpoints ──
    {
        "label": "Blog Settings",
        "path": "/api/v2/blog/{BLOG}/settings",
        "method": "GET",
        "severity": "HIGH",
        "notes": "Should return 403 for non-owner. Contains email, monetization settings.",
        "pii_keys": ["email", "advertiser_email", "monetization", "password_protected"],
    },
    {
        "label": "Blog Notifications",
        "path": "/api/v2/blog/{BLOG}/notifications",
        "method": "GET",
        "severity": "MEDIUM",
        "notes": "Private notification feed — visible only to blog owner.",
        "pii_keys": ["timeline", "notifications", "follower_uuid"],
    },
    {
        "label": "Activity Last Read",
        "path": "/api/v2/blog/{BLOG}/activity_last_read",
        "method": "GET",
        "severity": "LOW",
        "notes": "Timestamp leak — minor but confirms auth bypass.",
        "pii_keys": ["last_read", "timestamp"],
    },
    {
        "label": "Activity Notes (3-day/hourly)",
        "path": "/api/v2/blog/{BLOG}/activity/notes/threedays/hourly",
        "method": "GET",
        "severity": "MEDIUM",
        "notes": "Analytics on blog activity — private engagement data.",
        "pii_keys": ["notes", "count", "hourly"],
    },
    {
        "label": "Tag Suggestions",
        "path": "/api/v2/blog/{BLOG}/posts/tag_suggestions",
        "method": "GET",
        "severity": "LOW",
        "notes": "Draft-based tag suggestions may reveal unpublished content topics.",
        "pii_keys": ["tags", "suggestions"],
    },
    {
        "label": "Drafts",
        "path": "/api/v2/blog/{BLOG}/posts/draft",
        "method": "GET",
        "severity": "HIGH",
        "notes": "CRITICAL — unpublished draft posts. Clear IDOR if accessible.",
        "pii_keys": ["posts", "draft", "body", "content"],
    },
    {
        "label": "Queue",
        "path": "/api/v2/blog/{BLOG}/posts/queue",
        "method": "GET",
        "severity": "HIGH",
        "notes": "Scheduled posts — private until published.",
        "pii_keys": ["posts", "queue"],
    },
    {
        "label": "Submissions",
        "path": "/api/v2/blog/{BLOG}/posts/submission",
        "method": "GET",
        "severity": "MEDIUM",
        "notes": "Submitted posts awaiting approval.",
        "pii_keys": ["posts", "submission"],
    },
    {
        "label": "Filtered Content",
        "path": "/api/v2/blog/{BLOG}/content_filter",
        "method": "GET",
        "severity": "LOW",
        "notes": "Private content filter settings.",
        "pii_keys": ["filtered", "blocked"],
    },
    {
        "label": "Blog Info (admin fields)",
        "path": "/api/v2/blog/{BLOG}/info?fields[blogs]=?admin,?advertiser_name,?allow_search_indexing,?analytics_url,name,url",
        "method": "GET",
        "severity": "MEDIUM",
        "notes": "Admin-gated fields like analytics_url in the response indicate elevated access.",
        "pii_keys": ["admin", "analytics_url", "advertiser_name"],
    },
    # ── User-scoped private endpoints ──
    {
        "label": "User Birth Date (PII)",
        "path": "/api/v2/user/birth_date",
        "method": "GET",
        "severity": "HIGH",
        "notes": "Direct PII leak — date of birth. Authenticated endpoint.",
        "pii_keys": ["birth_date", "date", "age"],
    },
    {
        "label": "User Settings",
        "path": "/api/v2/user/settings",
        "method": "GET",
        "severity": "HIGH",
        "notes": "Full account settings — email, language, notification prefs.",
        "pii_keys": ["email", "default_post_format", "likes_visible", "following_visible"],
    },
    {
        "label": "User Session",
        "path": "/api/v2/user/session",
        "method": "GET",
        "severity": "HIGH",
        "notes": "Current session details — user ID, blog associations.",
        "pii_keys": ["user", "uuid", "id", "email"],
    },
    {
        "label": "User Counts",
        "path": "/api/v2/user/counts?blog_post_counts=true",
        "method": "GET",
        "severity": "LOW",
        "notes": "Private stat counters per blog.",
        "pii_keys": ["counts", "total_posts"],
    },
    {
        "label": "Followed Tags",
        "path": "/api/v2/user/followed_tags?format=short&sort_order=asc&sort=tag_name",
        "method": "GET",
        "severity": "MEDIUM",
        "notes": "Private tag follows — reveals interests/identity.",
        "pii_keys": ["tags", "followed"],
    },
    {
        "label": "Activity Filters",
        "path": "/api/v2/activity/filters",
        "method": "GET",
        "severity": "MEDIUM",
        "notes": "Activity filter configuration — account-level setting.",
        "pii_keys": ["filters", "activity"],
    },
    {
        "label": "Premium Subscription",
        "path": "/api/v2/premium/subscription",
        "method": "GET",
        "severity": "MEDIUM",
        "notes": "Subscription/billing status.",
        "pii_keys": ["subscription", "plan", "renewal_date", "billing"],
    },
    {
        "label": "Tumblrmart Unseen Items",
        "path": "/api/v2/tumblrmart/unseen_items",
        "method": "GET",
        "severity": "LOW",
        "notes": "Private shop state.",
        "pii_keys": ["unseen", "items"],
    },
    {
        "label": "TAuth Details",
        "path": "/api/v2/tauth/details",
        "method": "GET",
        "severity": "HIGH",
        "notes": "Auth token details — may expose token information.",
        "pii_keys": ["token", "key", "secret", "auth"],
    },
    {
        "label": "Privacy Consent",
        "path": "/api/v2/privacy/consent",
        "method": "GET",
        "severity": "LOW",
        "notes": "GDPR consent state — per-account.",
        "pii_keys": ["consent", "gdpr", "accepted"],
    },
]

BASE_URL = "https://www.tumblr.com"

HEADERS_BASE = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Accept-Language": "en-US,en;q=0.9",
    "X-Requested-With": "XMLHttpRequest",
    "Referer": "https://www.tumblr.com/",
}

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

SEVERITY_COLOR = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m"}
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
DIM = "\033[2m"

def color(text, code): return f"{code}{text}{RESET}"


def parse_cookie_string(raw: str) -> dict:
    """Parse 'key=val; key=val; ...' into a dict."""
    cookies = {}
    for part in raw.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            cookies[k.strip()] = v.strip()
    return cookies


def extract_csrf_token(cookie_dict: dict) -> str | None:
    """Try to find a CSRF token in cookies."""
    for k in ["tumblr_form_key", "csrf_token", "form_key"]:
        if k in cookie_dict:
            return cookie_dict[k]
    return None


def make_request(url: str, cookies: dict, csrf: str | None, method: str = "GET", verbose: bool = False) -> dict:
    """Make a single request and return a structured result dict."""
    headers = dict(HEADERS_BASE)
    if csrf:
        headers["X-CSRF-Token"] = csrf

    result = {
        "status": None,
        "size": 0,
        "body": "",
        "json": None,
        "error": None,
        "elapsed_ms": 0,
    }

    try:
        t0 = time.time()
        resp = requests.request(
            method,
            url,
            headers=headers,
            cookies=cookies,
            timeout=15,
            allow_redirects=False,
        )
        result["elapsed_ms"] = int((time.time() - t0) * 1000)
        result["status"] = resp.status_code
        result["size"] = len(resp.content)
        result["body"] = resp.text[:4000]  # cap to first 4K
        try:
            result["json"] = resp.json()
        except Exception:
            result["json"] = None
    except RequestException as e:
        result["error"] = str(e)

    if verbose:
        status_color = GREEN if result["status"] and result["status"] < 300 else YELLOW
        print(f"    {DIM}→ {method} {url}{RESET}")
        print(f"      status={color(str(result['status']), status_color)} "
              f"size={result['size']} ms={result['elapsed_ms']}")

    return result


def detect_pii(body: str, pii_keys: list[str]) -> list[str]:
    """Look for known sensitive field patterns in response body."""
    found = []
    lower = body.lower()
    for key in pii_keys:
        if f'"{key}"' in lower or f"'{key}'" in lower:
            found.append(key)
    # Generic PII patterns
    email_pat = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    date_pat  = re.compile(r'\b\d{4}-\d{2}-\d{2}\b')
    if email_pat.search(body):
        found.append("⚠ email-address-in-body")
    if date_pat.search(body):
        found.append("⚠ date-in-body")
    return list(set(found))


def classify_result(victim_r: dict, attacker_r: dict, no_auth_r: dict) -> str:
    """
    Classify the IDOR likelihood:
      IDOR_CONFIRMED  — attacker gets 200 AND similar body size as victim
      IDOR_POSSIBLE   — attacker gets 200 but smaller/different response
      PROTECTED       — attacker gets 403/401/302
      INTERESTING     — no-auth also gets 200 (misconfigured endpoint, worth noting)
      ERROR           — request failed
    """
    if victim_r["error"] or attacker_r["error"]:
        return "ERROR"

    v_status = victim_r["status"] or 0
    a_status = attacker_r["status"] or 0
    n_status = no_auth_r["status"] or 0
    v_size   = victim_r["size"]
    a_size   = attacker_r["size"]

    if a_status == 200 and v_status == 200:
        size_ratio = min(a_size, v_size) / max(a_size, v_size, 1)
        if size_ratio > 0.7:
            return "IDOR_CONFIRMED"
        else:
            return "IDOR_POSSIBLE"
    elif a_status == 200 and v_status != 200:
        return "IDOR_POSSIBLE"   # victim couldn't reach it either, but still worth noting
    elif a_status in (401, 403):
        if n_status == 200:
            return "INTERESTING"  # broken auth — public but shouldn't be
        return "PROTECTED"
    elif a_status in (301, 302, 308):
        return "PROTECTED"  # login redirect
    else:
        return "INTERESTING"


STATUS_ICON = {
    "IDOR_CONFIRMED": "🔴 IDOR CONFIRMED",
    "IDOR_POSSIBLE":  "🟡 IDOR POSSIBLE",
    "PROTECTED":      "🟢 PROTECTED",
    "INTERESTING":    "🔵 INTERESTING",
    "ERROR":          "⚪ ERROR",
}

# ─────────────────────────────────────────────────────────────
# HTML REPORT
# ─────────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Tumblr IDOR Probe Report — {timestamp}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e;
    --red: #f85149; --yellow: #d29922; --green: #56d364; --blue: #58a6ff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }}
  h1 {{ color: var(--blue); font-size: 1.5rem; margin-bottom: 0.5rem; }}
  .meta {{ color: var(--muted); font-size: 0.85rem; margin-bottom: 2rem; }}
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }}
  .stat .num {{ font-size: 2rem; font-weight: bold; }}
  .stat .lbl {{ font-size: 0.75rem; color: var(--muted); margin-top: 0.25rem; }}
  .red {{ color: var(--red); }} .yellow {{ color: var(--yellow); }}
  .green {{ color: var(--green); }} .blue {{ color: var(--blue); }}
  .endpoint {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
               margin-bottom: 1rem; overflow: hidden; }}
  .ep-header {{ display: flex; align-items: center; gap: 1rem; padding: 0.75rem 1rem;
               border-bottom: 1px solid var(--border); cursor: pointer; }}
  .ep-header:hover {{ background: #1c2128; }}
  .badge {{ padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; white-space: nowrap; }}
  .badge-red {{ background: #3d1f21; color: var(--red); border: 1px solid var(--red); }}
  .badge-yellow {{ background: #2d2109; color: var(--yellow); border: 1px solid var(--yellow); }}
  .badge-green {{ background: #1a2e1a; color: var(--green); border: 1px solid var(--green); }}
  .badge-blue {{ background: #1a2438; color: var(--blue); border: 1px solid var(--blue); }}
  .badge-gray {{ background: #1c2128; color: var(--muted); border: 1px solid var(--border); }}
  .sev-HIGH {{ color: var(--red); }}
  .sev-MEDIUM {{ color: var(--yellow); }}
  .sev-LOW {{ color: var(--blue); }}
  .ep-body {{ display: none; padding: 1rem; }}
  .ep-body.open {{ display: block; }}
  .grid3 {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem; margin-top: 1rem; }}
  .req-box {{ background: #0d1117; border: 1px solid var(--border); border-radius: 6px; padding: 0.75rem; }}
  .req-box h4 {{ font-size: 0.8rem; color: var(--muted); margin-bottom: 0.5rem; }}
  .status-pill {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
                  font-size: 0.8rem; font-weight: bold; margin-bottom: 0.5rem; }}
  .s2xx {{ background: #1a2e1a; color: var(--green); }}
  .s3xx {{ background: #1a2438; color: var(--blue); }}
  .s4xx {{ background: #3d1f21; color: var(--red); }}
  pre {{ background: #070c10; border: 1px solid var(--border); border-radius: 4px;
         padding: 0.5rem; font-size: 0.72rem; overflow-x: auto; max-height: 200px;
         color: #abb2bf; line-height: 1.4; white-space: pre-wrap; word-break: break-all; }}
  .pii-tags {{ margin-top: 0.5rem; display: flex; flex-wrap: wrap; gap: 0.25rem; }}
  .pii-tag {{ background: #3d2809; color: #e3a54a; border: 1px solid #e3a54a;
               border-radius: 3px; font-size: 0.7rem; padding: 0.1rem 0.4rem; }}
  .notes {{ font-size: 0.82rem; color: var(--muted); margin-top: 0.75rem; font-style: italic; }}
  footer {{ margin-top: 3rem; text-align: center; color: var(--muted); font-size: 0.8rem; }}
  .toggle-hint {{ font-size: 0.75rem; color: var(--muted); margin-left: auto; }}
</style>
</head>
<body>
<h1>🔍 Tumblr IDOR Probe Report</h1>
<div class="meta">
  Target blog: <strong>{victim_blog}</strong> &nbsp;|&nbsp;
  Scanned: <strong>{timestamp}</strong> &nbsp;|&nbsp;
  Endpoints tested: <strong>{total}</strong>
</div>
<div class="summary">
  <div class="stat"><div class="num red">{n_confirmed}</div><div class="lbl">IDOR CONFIRMED</div></div>
  <div class="stat"><div class="num yellow">{n_possible}</div><div class="lbl">IDOR POSSIBLE</div></div>
  <div class="stat"><div class="num green">{n_protected}</div><div class="lbl">PROTECTED</div></div>
  <div class="stat"><div class="num blue">{n_interesting}</div><div class="lbl">INTERESTING</div></div>
</div>
{endpoint_sections}
<footer>Generated by tumblr-idor-probe.py &nbsp;·&nbsp; github.com/MhndFi/MyTools &nbsp;·&nbsp; @DaemaAI</footer>
<script>
document.querySelectorAll('.ep-header').forEach(h => {{
  h.addEventListener('click', () => {{
    h.nextElementSibling.classList.toggle('open');
  }});
}});
// Auto-expand findings
document.querySelectorAll('.ep-header').forEach(h => {{
  const badge = h.querySelector('.result-badge');
  if (badge && (badge.classList.contains('badge-red') || badge.classList.contains('badge-yellow'))) {{
    h.nextElementSibling.classList.add('open');
  }}
}});
</script>
</body>
</html>"""

EP_SECTION_TEMPLATE = """
<div class="endpoint">
  <div class="ep-header">
    <span class="result-badge badge {badge_class}">{result_label}</span>
    <strong>{label}</strong>
    <span class="sev-{severity}">[{severity}]</span>
    <span class="toggle-hint">▾ click to expand</span>
  </div>
  <div class="ep-body">
    <code style="font-size:0.8rem;color:#58a6ff;">{method} {path}</code>
    <div class="notes">{notes}</div>
    <div class="grid3">
      <div class="req-box">
        <h4>① VICTIM (own cookies)</h4>
        <span class="status-pill {victim_status_class}">{victim_status}</span>
        <div style="font-size:0.75rem;color:#8b949e;">size: {victim_size}b &nbsp; {victim_ms}ms</div>
        {victim_pii}
        <pre>{victim_body}</pre>
      </div>
      <div class="req-box">
        <h4>② ATTACKER (different account)</h4>
        <span class="status-pill {attacker_status_class}">{attacker_status}</span>
        <div style="font-size:0.75rem;color:#8b949e;">size: {attacker_size}b &nbsp; {attacker_ms}ms</div>
        {attacker_pii}
        <pre>{attacker_body}</pre>
      </div>
      <div class="req-box">
        <h4>③ UNAUTHENTICATED</h4>
        <span class="status-pill {noauth_status_class}">{noauth_status}</span>
        <div style="font-size:0.75rem;color:#8b949e;">size: {noauth_size}b &nbsp; {noauth_ms}ms</div>
        <pre>{noauth_body}</pre>
      </div>
    </div>
  </div>
</div>"""


def status_css(code) -> str:
    if code is None: return "s4xx"
    if code < 300: return "s2xx"
    if code < 400: return "s3xx"
    return "s4xx"


def result_badge_class(result: str) -> str:
    return {
        "IDOR_CONFIRMED": "badge-red",
        "IDOR_POSSIBLE":  "badge-yellow",
        "PROTECTED":      "badge-green",
        "INTERESTING":    "badge-blue",
        "ERROR":          "badge-gray",
    }.get(result, "badge-gray")


def escape_html(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_pii_html(pii_list: list[str]) -> str:
    if not pii_list:
        return ""
    tags = "".join(f'<span class="pii-tag">{escape_html(p)}</span>' for p in pii_list)
    return f'<div class="pii-tags">{tags}</div>'


def generate_html(victim_blog: str, results: list[dict]) -> str:
    counts = {"IDOR_CONFIRMED": 0, "IDOR_POSSIBLE": 0, "PROTECTED": 0, "INTERESTING": 0, "ERROR": 0}
    for r in results:
        counts[r["classification"]] = counts.get(r["classification"], 0) + 1

    sections = ""
    for r in results:
        ep   = r["endpoint"]
        vr   = r["victim"]
        ar   = r["attacker"]
        nr   = r["no_auth"]
        cls  = r["classification"]

        sections += EP_SECTION_TEMPLATE.format(
            badge_class=result_badge_class(cls),
            result_label=STATUS_ICON.get(cls, cls),
            label=ep["label"],
            severity=ep["severity"],
            method=ep["method"],
            path=ep["path"],
            notes=escape_html(ep["notes"]),
            victim_status=vr["status"] or "ERR",
            victim_status_class=status_css(vr["status"]),
            victim_size=vr["size"],
            victim_ms=vr["elapsed_ms"],
            victim_pii=build_pii_html(r.get("victim_pii", [])),
            victim_body=escape_html((vr["body"] or "")[:800]),
            attacker_status=ar["status"] or "ERR",
            attacker_status_class=status_css(ar["status"]),
            attacker_size=ar["size"],
            attacker_ms=ar["elapsed_ms"],
            attacker_pii=build_pii_html(r.get("attacker_pii", [])),
            attacker_body=escape_html((ar["body"] or "")[:800]),
            noauth_status=nr["status"] or "ERR",
            noauth_status_class=status_css(nr["status"]),
            noauth_size=nr["size"],
            noauth_ms=nr["elapsed_ms"],
            noauth_body=escape_html((nr["body"] or "")[:400]),
        )

    return HTML_TEMPLATE.format(
        victim_blog=victim_blog,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total=len(results),
        n_confirmed=counts["IDOR_CONFIRMED"],
        n_possible=counts["IDOR_POSSIBLE"],
        n_protected=counts["PROTECTED"],
        n_interesting=counts["INTERESTING"],
        endpoint_sections=sections,
    )


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def banner():
    print(f"""
{BOLD}\033[95m  ████████╗██╗   ██╗███╗   ███╗██████╗ ██╗      ██████╗
     ██╔══╝ ██║   ██║████╗ ████║██╔══██╗██║     ██╔══██╗
     ██║    ██║   ██║██╔████╔██║██████╔╝██║     ██████╔╝
     ██║    ██║   ██║██║╚██╔╝██║██╔══██╗██║     ██╔══██╗
     ██║    ╚██████╔╝██║ ╚═╝ ██║██████╔╝███████╗██║  ██║
     ╚═╝     ╚═════╝ ╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝{RESET}
  {color('IDOR Probe', BOLD)} — Tumblr API Cross-Account Access Tester
  {DIM}github.com/MhndFi/MyTools | @DaemaAI{RESET}
""")


def main():
    parser = argparse.ArgumentParser(
        description="Tumblr API IDOR Scanner — tests cross-account endpoint access",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--victim-blog", required=True, help="Victim's Tumblr blog name (e.g. my-test-blog)")
    parser.add_argument("--victim-cookie", required=True, help="Victim account cookie string (copy from browser)")
    parser.add_argument("--attacker-cookie", required=True, help="Attacker account cookie string (second account)")
    parser.add_argument("--output-html", default="idor-report.html", help="HTML report output path (default: idor-report.html)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds (default: 0.5)")
    parser.add_argument("--verbose", action="store_true", help="Show individual request details")
    parser.add_argument("--only-findings", action="store_true", help="Only print non-PROTECTED results")
    args = parser.parse_args()

    banner()

    victim_cookies   = parse_cookie_string(args.victim_cookie)
    attacker_cookies = parse_cookie_string(args.attacker_cookie)
    victim_csrf      = extract_csrf_token(victim_cookies)
    attacker_csrf    = extract_csrf_token(attacker_cookies)

    print(f"  Target blog  : {color(args.victim_blog, BOLD)}")
    print(f"  Victim CSRF  : {color(str(victim_csrf), DIM)}")
    print(f"  Attacker CSRF: {color(str(attacker_csrf), DIM)}")
    print(f"  Endpoints    : {len(ENDPOINTS)}")
    print(f"  Delay        : {args.delay}s\n")
    print(f"  {'─'*60}")

    results = []
    findings = []

    for ep in ENDPOINTS:
        path = ep["path"].replace("{BLOG}", args.victim_blog)
        url  = BASE_URL + path
        sev_col = SEVERITY_COLOR.get(ep["severity"], "")

        print(f"\n  {color('[' + ep['label'] + ']', BOLD)} {color(ep['severity'], sev_col)}")
        print(f"  {DIM}{ep['method']} {path}{RESET}")

        # ① Victim (baseline)
        victim_r = make_request(url, victim_cookies, victim_csrf, ep["method"], args.verbose)
        time.sleep(args.delay)

        # ② Attacker (IDOR test)
        attacker_r = make_request(url, attacker_cookies, attacker_csrf, ep["method"], args.verbose)
        time.sleep(args.delay)

        # ③ No auth (misconfiguration check)
        no_auth_r = make_request(url, {}, None, ep["method"], args.verbose)
        time.sleep(args.delay)

        cls = classify_result(victim_r, attacker_r, no_auth_r)
        victim_pii   = detect_pii(victim_r["body"] or "", ep["pii_keys"])
        attacker_pii = detect_pii(attacker_r["body"] or "", ep["pii_keys"])

        icon = STATUS_ICON.get(cls, cls)
        v_s  = color(str(victim_r["status"]),   GREEN if victim_r["status"] == 200 else YELLOW)
        a_s  = color(str(attacker_r["status"]), RED   if attacker_r["status"] == 200 else GREEN)
        n_s  = color(str(no_auth_r["status"]),  RED   if no_auth_r["status"] == 200 else DIM)

        print(f"  {icon}")
        print(f"  victim={v_s}({victim_r['size']}b)  attacker={a_s}({attacker_r['size']}b)  noauth={n_s}({no_auth_r['size']}b)")

        if attacker_pii:
            print(f"  {YELLOW}⚠ PII keys in attacker response: {', '.join(attacker_pii)}{RESET}")

        r = {
            "endpoint": ep,
            "victim": victim_r,
            "attacker": attacker_r,
            "no_auth": no_auth_r,
            "classification": cls,
            "victim_pii": victim_pii,
            "attacker_pii": attacker_pii,
        }
        results.append(r)

        if cls in ("IDOR_CONFIRMED", "IDOR_POSSIBLE", "INTERESTING"):
            findings.append(r)

    # ── Summary ──
    print(f"\n\n  {'═'*60}")
    print(f"  {BOLD}SCAN COMPLETE{RESET}")
    print(f"  {'─'*60}")

    by_class = {}
    for r in results:
        by_class.setdefault(r["classification"], []).append(r["endpoint"]["label"])

    for cls, labels in by_class.items():
        icon = STATUS_ICON.get(cls, cls)
        for lbl in labels:
            ep_sev = next(e["severity"] for e in ENDPOINTS if e["label"] == lbl)
            print(f"  {icon}  {color(lbl, BOLD)} [{ep_sev}]")

    n_c = len(by_class.get("IDOR_CONFIRMED", []))
    n_p = len(by_class.get("IDOR_POSSIBLE", []))
    n_s = len(by_class.get("PROTECTED", []))
    n_i = len(by_class.get("INTERESTING", []))
    print(f"\n  {color(f'🔴 IDOR CONFIRMED: {n_c}', RED)}")
    print(f"  {color(f'🟡 IDOR POSSIBLE:  {n_p}', YELLOW)}")
    print(f"  {color(f'🟢 PROTECTED:      {n_s}', GREEN)}")
    print(f"  {color(f'🔵 INTERESTING:    {n_i}', BOLD)}")

    # ── HTML Report ──
    html = generate_html(args.victim_blog, results)
    out_path = Path(args.output_html)
    out_path.write_text(html, encoding="utf-8")
    print(f"\n  {GREEN}✓ HTML report saved → {out_path.absolute()}{RESET}")
    print(f"  Open in browser for full evidence (screenshot for HackerOne PoC)")

    if findings:
        print(f"\n  {YELLOW}{BOLD}⚡ {len(findings)} finding(s) worth investigating further!{RESET}")
        print(f"  {DIM}Next: build PoC showing real PII extraction for report.{RESET}")
    else:
        print(f"\n  {DIM}No IDORs found this run. Try different endpoint list or check recon.{RESET}")


if __name__ == "__main__":
    main()
