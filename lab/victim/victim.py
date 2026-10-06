from __future__ import annotations

import datetime as dt
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import ThreadingTCPServer, StreamRequestHandler

LOG_PATH = os.environ.get("VICTIM_LOG", "/logs/victim.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)


def write_log(message: str) -> None:
    timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
    line = f"{timestamp} {message}\n"
    with open(LOG_PATH, "a", encoding="utf-8") as handle:
        handle.write(line)
        handle.flush()
    print(line, end="", flush=True)


class SSHLikeHandler(StreamRequestHandler):
    def handle(self) -> None:
        self.wfile.write(b"SENTINEL-VICTIM SSH LAB\nlogin format: LOGIN <user> <password>\n")
        self.wfile.flush()
        raw = self.rfile.readline(256).decode("utf-8", errors="replace").strip()
        parts = raw.split()
        username = parts[1] if len(parts) > 1 else "unknown"
        password = parts[2] if len(parts) > 2 else ""
        peer = self.client_address[0]
        if username == "demo" and password == "lab-only-password":
            write_log(f"AUTH_SUCCESS src={peer} user={username} service=ssh action=login")
            self.wfile.write(b"AUTH OK lab session opened\n")
        else:
            write_log(f"AUTH_FAIL src={peer} user={username} service=ssh reason=invalid_credentials")
            self.wfile.write(b"AUTH FAILED\n")
        self.wfile.flush()


import urllib.parse


class WebHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self._handle_request()

    def do_POST(self) -> None:
        self._handle_request()

    def do_HEAD(self) -> None:
        self._handle_request()

    def _handle_request(self) -> None:
        peer = self.client_address[0]
        decoded_path = urllib.parse.unquote(self.path)
        write_log(f"WEB_REQUEST client={peer} method={self.command} path={decoded_path} raw_path={self.path}")

        if self.path == "/health":
            body = b"victim-ok\n"
            status = 200
        elif "' OR 1=1" in decoded_path or "1=1" in decoded_path or "UNION SELECT" in decoded_path.upper():
            body = b"HTTP 500 Internal Server Error: SQL syntax error near 'OR 1=1'\n"
            status = 500
        elif "../" in decoded_path or "..\\" in decoded_path:
            body = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            status = 200
        else:
            body = b"SentinelGraph isolated victim web surface\n"
            status = 200

        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


if __name__ == "__main__":
    write_log("VICTIM_READY ssh=2222 web=8080 environment=isolated-lab")
    ssh_server = ThreadingTCPServer(("0.0.0.0", 2222), SSHLikeHandler)
    web_server = ThreadingHTTPServer(("0.0.0.0", 8080), WebHandler)
    threading.Thread(target=ssh_server.serve_forever, daemon=True).start()
    threading.Thread(target=web_server.serve_forever, daemon=True).start()
    threading.Event().wait()
