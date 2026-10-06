from __future__ import annotations

import json
import os
import time
import urllib.request

LOG_PATH = os.environ.get("VICTIM_LOG", "/logs/victim.log")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "http://platform:8000/alerts")


def post_alert(line: str, rule: str, severity: int, source_host: str = "victim") -> None:
    payload = {
        "source_host": source_host,
        "rule": rule,
        "severity": severity,
        "raw_log_reference": f"victim.log:{line.strip()}",
        "detector": "sentinelgraph-edr-agent",
        "source": "production-enclave",
        "raw_payload": {"log_line": line.strip(), "detector_engine": "edr-signature-v2", "threat_score": severity},
    }
    request = urllib.request.Request(
        WEBHOOK_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        print(f"detector posted {response.status}: {rule} (host={source_host})", flush=True)


while not os.path.exists(LOG_PATH):
    time.sleep(0.5)

with open(LOG_PATH, "r", encoding="utf-8") as log_file:
    while True:
        line = log_file.readline()
        if not line:
            time.sleep(0.25)
            continue
        if "AUTH_FAIL" in line:
            post_alert(line, "ssh_brute_force_failed_login", 6, source_host="victim")
        elif "AUTH_SUCCESS" in line:
            post_alert(line, "ssh_success_after_failures", 9, source_host="victim")
        elif "WEB_REQUEST" in line:
            # Detect suspicious SQL Injection or Path Traversal
            upper_line = line.upper()
            if "' OR 1=1" in line or "1=1" in line or "UNION SELECT" in upper_line:
                post_alert(line, "web_sqli_injection_attempt", 8, source_host="web-portal")
            elif "../" in line or "..\\" in line or "..%2F" in upper_line:
                post_alert(line, "web_path_traversal_attempt", 8, source_host="web-portal")
            elif "${JNDI" in upper_line or "<SCRIPT" in upper_line:
                post_alert(line, "web_exploit_attempt", 8, source_host="web-portal")
            elif "/health" not in line:
                post_alert(line, "web_request_observed", 2, source_host="web-portal")

