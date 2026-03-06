# MyTools

Collection of small tools, scripts, and resources used during **bug bounty hunting, recon, and security testing**.

This repository contains automation scripts, payload generators, wordlists, and helper utilities that speed up common security research tasks.

---

# Contents

## Recon & Enumeration

### `ffuf-subdomains.sh`

Automates **subdomain fuzzing** using `ffuf`.

Typical usage:

```
./ffuf-subdomains.sh target.com
```

Used with large wordlists such as `subdomains-top1million-*`.

---

### `gau`

Binary/tool for collecting **historical URLs** from public sources.

Useful for discovering:

* old endpoints
* hidden parameters
* deprecated APIs

Example:

```
gau target.com
```

---

### `rustscan`

Fast **port scanning tool** written in Rust.

Common workflow:

```
rustscan -a target.com
```

Often used before deeper scanning with `nmap`.

---

# Bug Bounty Utilities

### `apiman-probe.py`

Script designed to test **APIMAN cart endpoints** for potential authentication or IDOR issues.

Helps quickly probe API endpoints that may expose unauthorized access to cart data.

---

### `ssrf-payload-gen.py`

Generates payloads used when testing **SSRF vulnerabilities**.

Useful for:

* internal network probing
* metadata access attempts
* cloud SSRF testing

---

### `webSocket-SSRF-myserver.py`

Local server used when testing **WebSocket SSRF scenarios**.

Helps capture and analyze server-side WebSocket requests triggered by SSRF vulnerabilities.

---

# Networking & Local Testing

### `pythonHTTPS-server.py`

Simple Python HTTPS server for local testing.

Useful for:

* SSRF testing
* callback listeners
* local payload hosting

---

### `receiver.py`

Script used as a **listener / receiver** for incoming requests during testing.

Can capture:

* callbacks
* exfiltration attempts
* SSRF traffic

---

# Post Exploitation / Pentesting

### `linpeas.sh`

Privilege escalation enumeration tool for Linux systems.

Common usage after gaining shell access.

---

### `php-reverse-shell-1.0.tar.gz`

PHP reverse shell payload used for testing command execution vulnerabilities.

---

# Wordlists

Included wordlists for fuzzing and enumeration:

* `big.txt`
* `directory-list-2.3-big.txt`
* `subdomains-top1million-5000.txt`
* `subdomains-top1million-20000.txt`
* `subdomains-top1million-110000.txt`

These are used with tools like:

* `ffuf`
* `dirsearch`
* `gobuster`

---

# Misc

### `mhndfi_was_here.html`

Test HTML page used for quick deployment or verification during testing.

---

# Reverse Tabnabbing

Folder containing files related to **reverse tabnabbing testing**.

Reverse tabnabbing occurs when a page opened with `target="_blank"` can modify the original page using `window.opener`.

---

# Author

Mohannad Firon
Bug bounty hunter and web security researcher.

---

# Disclaimer

All tools in this repository are intended for **educational purposes and authorized security testing only**.

Do not use these tools against systems without permission.
