"""
The scan target: a web server announcing an old Apache version and an SSH
service announcing an old OpenSSH, so NetScan finds services, reads their
versions and matches CVEs. Nothing here is actually vulnerable.
"""

import socketserver
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

SSH_BANNER = b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n"


class WebServer(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.49"
    sys_version = ""

    def do_GET(self):
        body = b"<h1>Lab target</h1>\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

    def log_message(self, fmt, *args):
        print(f"[web] {self.client_address[0]} {fmt % args} UA={self.headers.get('User-Agent')!r}", flush=True)


class SshBanner(socketserver.BaseRequestHandler):
    def handle(self):
        print(f"[ssh] connection from {self.client_address[0]}", flush=True)
        self.request.sendall(SSH_BANNER)


if __name__ == "__main__":
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    ssh = socketserver.ThreadingTCPServer(("0.0.0.0", 22), SshBanner)
    threading.Thread(target=ssh.serve_forever, daemon=True).start()
    print("[target] web on :80 (Apache/2.4.49), ssh banner on :22 (OpenSSH 7.4p1)", flush=True)
    HTTPServer(("0.0.0.0", 80), WebServer).serve_forever()
