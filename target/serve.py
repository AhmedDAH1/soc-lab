"""
The scan target: a web server announcing an old Apache version and an SSH
service announcing an old OpenSSH, so NetScan finds services, reads their
versions and matches CVEs. Nothing here is actually vulnerable.
"""

import json
import os
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

SSH_BANNER = b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n"
LAB_EVENTS = Path(os.environ.get("LAB_DIR", "/lab")) / "events"


def report(kind, **data):
    """Tell the lab's live console what the target just answered. Optional: never raises."""
    try:
        if LAB_EVENTS.is_dir():
            with (LAB_EVENTS / "target.jsonl").open("a", encoding="utf-8") as f:
                f.write(json.dumps({"ts": time.time(), "stage": "target", "kind": kind, **data}) + "\n")
    except (OSError, TypeError, ValueError):
        pass


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
        report("http", client=self.client_address[0], request=getattr(self, "requestline", "")[:200],
               agent=(self.headers.get("User-Agent") or "")[:200] if getattr(self, "headers", None) else "",
               server=self.server_version)


class SshBanner(socketserver.BaseRequestHandler):
    def handle(self):
        print(f"[ssh] connection from {self.client_address[0]}", flush=True)
        self.request.sendall(SSH_BANNER)
        report("ssh", client=self.client_address[0], banner=SSH_BANNER.decode().strip())


if __name__ == "__main__":
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    ssh = socketserver.ThreadingTCPServer(("0.0.0.0", 22), SshBanner)
    threading.Thread(target=ssh.serve_forever, daemon=True).start()
    print("[target] web on :80 (Apache/2.4.49), ssh banner on :22 (OpenSSH 7.4p1)", flush=True)
    HTTPServer(("0.0.0.0", 80), WebServer).serve_forever()
