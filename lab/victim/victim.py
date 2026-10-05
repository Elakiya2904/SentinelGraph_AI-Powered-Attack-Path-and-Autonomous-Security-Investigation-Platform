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


class WebHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/health":
            body = b"victim-ok"
            self.send_response(200)
        else:
            body = b"SentinelGraph isolated victim web surface"
            self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        write_log(f"WEB_REQUEST client={self.client_address[0]} path={self.path}")


if __name__ == "__main__":
    write_log("VICTIM_READY ssh=2222 web=8080 environment=isolated-lab")
    ssh_server = ThreadingTCPServer(("0.0.0.0", 2222), SSHLikeHandler)
    web_server = ThreadingHTTPServer(("0.0.0.0", 8080), WebHandler)
    threading.Thread(target=ssh_server.serve_forever, daemon=True).start()
    threading.Thread(target=web_server.serve_forever, daemon=True).start()
    threading.Event().wait()
