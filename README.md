# MyTools — Bug Bounty Toolkit

Personal collection of scripts built during active bug bounty hunting.

---

## 🔍 tumblr-idor-probe.py

**Tumblr API cross-account IDOR scanner** — automates two-account IDOR testing against Tumblr's private API endpoints with HTML evidence report generation.

### What it does

- Tests **20 sensitive Tumblr API endpoints** that should be owner-only
- Makes 3 requests per endpoint: victim (baseline) → attacker → unauthenticated
- Classifies each result: **IDOR_CONFIRMED / IDOR_POSSIBLE / PROTECTED / INTERESTING**
- Detects PII in attacker responses (emails, dates, account data)
- Generates a **dark-mode HTML report** ready for HackerOne PoC screenshots

### Endpoint categories

| Category | Endpoints |
|----------|-----------|
| Blog private | Settings, Notifications, Activity, Drafts, Queue, Submissions |
| User PII | Birth date, User settings, Session info, Followed tags |
| Auth/billing | TAuth details, Premium subscription, Privacy consent |

### Usage

```bash
# Basic scan
python3 tumblr-idor-probe.py \
  --victim-blog  your-test-blog \
  --victim-cookie  "pfp=abc; logged_in=1; ..." \
  --attacker-cookie "pfp=xyz; logged_in=1; ..."

# Save HTML report
python3 tumblr-idor-probe.py \
  --victim-blog  your-test-blog \
  --victim-cookie  "..." \
  --attacker-cookie "..." \
  --output-html  poc-report.html \
  --delay 1.0 \
  --verbose
```

### Getting cookies

1. Log in to Tumblr as Account 1 (victim)
2. Open DevTools → Application → Cookies
3. Copy all `tumblr.com` cookies as a single string
4. Repeat for Account 2 (attacker)

### Requirements

```bash
pip3 install requests
```

---

## 🌐 ssrf-payload-gen.py

**SSRF payload generator** — covers cloud metadata (AWS/GCP/Azure), internal services, protocol confusion, and IP encoding bypass techniques.

### Usage

```bash
# All payloads (default)
python3 ssrf-payload-gen.py

# Cloud metadata only
python3 ssrf-payload-gen.py --mode cloud

# Generate blind SSRF canary payloads
python3 ssrf-payload-gen.py --mode canary --canary-url your-id.oast.pro

# Save as wordlist for ffuf
python3 ssrf-payload-gen.py --mode all --format ffuf --output ssrf-wordlist.txt

# Show Tumblr-specific URL params
python3 ssrf-payload-gen.py --mode targets
```

### Modes

| Mode | Description |
|------|-------------|
| `all` | Everything (default) |
| `cloud` | AWS/GCP/Azure/DO metadata endpoints |
| `internal` | Localhost, RFC-1918, common service ports |
| `bypass` | IP encoding, protocol tricks, IPv6 |
| `targets` | Tumblr-specific URL-accepting parameters |
| `canary` | Blind SSRF payloads for your interactsh domain |

---

## Other tools

| File | Description |
|------|-------------|
| `ffuf-subdomains.sh` | Subdomain fuzzing helper |
| `webSocket-SSRF-myserver.py` | WebSocket SSRF test server |
| `pythonHTTPS-server.py` | Quick HTTPS server for PoC hosting |

---

*Built during HackerOne bug bounty hunting (Automattic/Tumblr program)*  
*@DaemaAI*
