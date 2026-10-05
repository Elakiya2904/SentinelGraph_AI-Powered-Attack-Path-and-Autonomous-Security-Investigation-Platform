from __future__ import annotations

import socket
import time

TARGET_HOST = "victim"
TARGET_PORT = 2222


def try_login(user: str, password: str) -> None:
    with socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=5) as connection:
        connection.recv(256)
        connection.sendall(f"LOGIN {user} {password}\n".encode("utf-8"))
        print(connection.recv(256).decode("utf-8", errors="replace").strip(), flush=True)


print(f"SAFE DEMO: target={TARGET_HOST}:{TARGET_PORT} (Compose network only)", flush=True)
for attempt in range(1, 4):
    try_login("demo", f"wrong-{attempt}")
    time.sleep(0.3)
try_login("demo", "lab-only-password")
print("SAFE DEMO COMPLETE: no external target was contacted", flush=True)
