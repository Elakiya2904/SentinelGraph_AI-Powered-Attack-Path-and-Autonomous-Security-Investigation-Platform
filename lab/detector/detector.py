from __future__ import annotations

import json
import os
import time
import urllib.request

LOG_PATH = os.environ.get("VICTIM_LOG", "/logs/victim.log")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "http://platform:8000/alerts")


def post_alert(line: str, rule: str, severity: int) -> None:
    payload = {
        "source_host": "victim",
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
        print(f"detector posted {response.status}: {rule}", flush=True)


while not os.path.exists(LOG_PATH):
    time.sleep(0.5)

with open(LOG_PATH, "r", encoding="utf-8") as log_file:
    while True:
        line = log_file.readline()
        if not line:
            time.sleep(0.25)
            continue
        if "AUTH_FAIL" in line:
            post_alert(line, "ssh_brute_force_failed_login", 6)
        elif "AUTH_SUCCESS" in line:
            post_alert(line, "ssh_success_after_failures", 9)
        elif "WEB_REQUEST" in line:
            post_alert(line, "web_request_observed", 3)
