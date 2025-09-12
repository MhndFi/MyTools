import http.server
import ssl
import argparse
import json
import os
from OpenSSL import crypto

# --- Certificate Generation ---
# This function generates a self-signed SSL certificate and a private key if they don't exist.
# This avoids the hassle of creating them manually every time you run the server.
def generate_self_signed_cert(cert_file, key_file):
    """Generates a self-signed certificate and key if they don't exist."""
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print(f"Generating self-signed certificate '{cert_file}' and key '{key_file}'...")

        # Create a new key pair
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        # Create a self-signed certificate
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "California"
        cert.get_subject().L = "San Francisco"
        cert.get_subject().O = "MyOrg"
        cert.get_subject().OU = "MyUnit"
        cert.get_subject().CN = "localhost" # The Common Name
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60) # Valid for 10 years
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')

        with open(cert_file, "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
        with open(key_file, "wt") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("utf-8"))
        print("Certificate and key generated successfully.")


# --- Custom Request Handler ---
# This class defines how the server will respond to GET and POST requests.
class SimpleHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    
    # Handler for GET requests
    def do_GET(self):
        print(f"[+] Received GET request from {self.client_address[0]}")
        
        # Set response headers
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        
        # Create a JSON response body to send back to the client
        response_data = {
            "status": "success",
            "message": "Server is alive and well!",
            "note": "Send a POST request to this server to see the data printed in the console."
        }
        
        # Write the response
        self.wfile.write(json.dumps(response_data).encode('utf-8'))

    # Handler for POST requests
    def do_POST(self):
        print(f"[+] Received POST request from {self.client_address[0]}")
        
        # Get the size of the incoming data
        content_length = int(self.headers['Content-Length'])
        # Read the data from the request body
        post_data = self.rfile.read(content_length)
        
        # Print the received data to the console (after decoding it from bytes to a string)
        print(f"    [+] Data Received: {post_data.decode('utf-8')}")
        
        # Send a success response back to the client
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        
        response_data = {"status": "success", "message": "Data received successfully."}
        self.wfile.write(json.dumps(response_data).encode('utf-8'))

    # Suppress the default log messages to keep the output clean
    def log_message(self, format, *args):
        return

# --- Main Execution Block ---
def main():
    # Set up the argument parser to accept an IP address from the command line
    parser = argparse.ArgumentParser(
        description="""
A simple, self-signed HTTPS server for receiving and sending data.
Ideal for cybersecurity labs, development, and CTF challenges.
The server will generate 'cert.pem' and 'key.pem' if they don't exist.
""",
        epilog="""
Usage examples:
  # Run on a specific local IP
  python3 httpserver.py --ip 192.168.1.10

  # Run on your VPN's IP address
  python3 httpserver.py --ip 10.10.0.5

  # Listen on all available network interfaces
  python3 httpserver.py --ip 0.0.0.0

  # Run on a custom port
  python3 httpserver.py --ip 127.0.0.1 --port 8443
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--ip', required=True, help="The IP address for the server to listen on.")
    parser.add_argument('--port', type=int, default=4443, help="The port for the server to listen on (default: 4443).")
    args = parser.parse_args()

    HOST = args.ip
    PORT = args.port
    CERT_FILE = "cert.pem"
    KEY_FILE = "key.pem"

    # Ensure we have SSL certs to use
    generate_self_signed_cert(CERT_FILE, KEY_FILE)

    # Create the server instance
    httpd = http.server.HTTPServer((HOST, PORT), SimpleHTTPRequestHandler)
    
    # --- Modern SSL/TLS Wrapping ---
    # Create a secure SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Load our self-signed certificate and key
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    
    # Wrap the server's socket with the SSL context
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    
    print(f"[*] HTTPS server starting on {HOST}:{PORT}...")
    print("[*] Use Ctrl+C to stop the server.")
    
    try:
        # Start the server and keep it running until interrupted
        httpd.serve_forever()
    except KeyboardInterrupt:
        # Handle graceful shutdown on Ctrl+C
        print("\n[*] Server is shutting down.")
        httpd.server_close()

if __name__ == "__main__":
    main()




