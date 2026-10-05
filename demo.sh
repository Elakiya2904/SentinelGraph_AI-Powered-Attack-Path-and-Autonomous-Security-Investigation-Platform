#!/usr/bin/env bash
set -euo pipefail

# SentinelGraph Safe Lab Demo Trigger
# Expected flow:
# ./demo.sh -> simulated attack -> victim log -> detector -> SentinelGraph /alerts -> terminal display -> dashboard investigation

# Determine Docker command and verify Docker daemon connection
if docker info >/dev/null 2>&1; then
  DOCKER_CMD="docker"
elif command -v docker.exe >/dev/null 2>&1 && docker.exe info >/dev/null 2>&1; then
  DOCKER_CMD="docker.exe"
else
  echo "[!] Error: Docker is not installed, or Docker daemon is unreachable."
  echo "    Please start Docker Desktop or the Docker daemon and retry."
  exit 1
fi

# Determine curl command
if command -v curl >/dev/null 2>&1; then
  CURL_CMD="curl"
elif command -v curl.exe >/dev/null 2>&1; then
  CURL_CMD="curl.exe"
else
  echo "[!] Error: 'curl' was not found in PATH."
  exit 1
fi

echo "================================================================="
echo "  SENTINELGRAPH DOCKER-BASED DEMO TRIGGER"
echo "================================================================="
echo "Using Docker CLI: $DOCKER_CMD"

# Step 1: Start required services: platform, victim, detector
echo "[1/4] Starting required lab services (platform, victim, detector)..."
if ! $DOCKER_CMD compose --progress=plain up -d platform victim detector >/dev/null 2>&1; then
  echo "[!] Error: Failed to start required Docker Compose services."
  exit 1
fi

# Step 2: Wait for platform webhook to become ready
echo "[2/4] Waiting for SentinelGraph platform webhook (http://127.0.0.1:8000/health)..."
READY=0
for i in $(seq 1 30); do
  if $CURL_CMD -fsS http://127.0.0.1:8000/health >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done

if [ "$READY" -ne 1 ]; then
  echo "[!] Error: SentinelGraph platform service failed to become ready within 30 seconds."
  echo "    Recent platform logs:"
  $DOCKER_CMD compose logs platform --tail 25
  exit 1
fi
echo "      Platform is online and ready to receive alerts."

# Step 3: Run the simulated attack strictly inside the isolated Docker network
echo ""
echo "[3/4] Triggering safe simulated attack against victim:2222..."
if ! $DOCKER_CMD compose --progress=plain --profile demo run --rm attacker; then
  echo "[!] Error: Failed to run simulated attacker container."
  exit 1
fi

# Step 4: Wait for detector to tail victim logs and post alerts to /alerts
echo "[4/4] Waiting for detector to post normalized alerts to SentinelGraph..."
sleep 2

# Display the generated alerts and important fields
FORMAT_SCRIPT='
import json, sys, urllib.request

try:
    with urllib.request.urlopen("http://127.0.0.1:8000/api/alerts", timeout=5) as res:
        data = json.loads(res.read().decode("utf-8"))
        alerts = data.get("alerts", [])
        queue_depth = data.get("queue_depth", 0)

    with urllib.request.urlopen("http://127.0.0.1:8000/api/investigation/current", timeout=5) as res:
        inv = json.loads(res.read().decode("utf-8"))

    if not alerts:
        print("[!] Warning: No alerts found in SentinelGraph queue.")
        sys.exit(1)

    print("")
    print("=" * 65)
    print("  GENERATED ALERTS & PIPELINE VERIFICATION")
    print("=" * 65)
    print("Total Alerts in Queue: " + str(queue_depth))
    print("-" * 65)

    for idx, a in enumerate(alerts[:3], start=1):
        print(f"[Alert {idx}]")
        print("  Alert ID:          " + str(a.get("alert_id")))
        print("  Source Host:       " + str(a.get("source_host")))
        print("  Rule Triggered:    " + str(a.get("rule")))
        print("  Severity:          " + str(a.get("severity")) + "/10")
        print("  Timestamp:         " + str(a.get("timestamp")))
        print("  Detector:          " + str(a.get("detector")))
        print("  Status:            " + str(a.get("status")))
        print("  Raw Log Reference: " + str(a.get("raw_log_reference")))
        print("-" * 65)

    run_id = inv.get("run_id")
    if run_id:
        print("INVESTIGATION TRIGGERED AUTOMATICALLY:")
        print("  Run ID:            " + str(run_id))
        print("  Status:            " + str(inv.get("status")))
        verdict = inv.get("verdict")
        if verdict:
            state = verdict.get("state")
            conf = int(verdict.get("confidence", 0) * 100)
            cov = int(verdict.get("evidence_coverage", 0) * 100)
            act = verdict.get("recommended_action")
            print(f"  Verdict:           {state} ({conf}% confidence)")
            print(f"  Evidence Coverage: {cov}%")
            print(f"  Action (Gated):    {act}")
        print("-" * 65)

    print("")
    print("Demo flow completed successfully:")
    print("  ./demo.sh -> simulated attack -> victim log -> detector -> SentinelGraph /alerts")
    print("")
    print("Next steps:")
    print("  - Open the live SOC dashboard: http://localhost:3000")
    print("  - To stop the lab: docker compose down -v")
    print("")

except Exception as exc:
    print(f"[!] Error fetching/formatting alerts: {exc}")
    sys.exit(1)
'

if command -v python3 >/dev/null 2>&1; then
  python3 -c "$FORMAT_SCRIPT"
elif command -v python >/dev/null 2>&1; then
  python -c "$FORMAT_SCRIPT"
else
  $DOCKER_CMD compose exec -T platform python -c "$FORMAT_SCRIPT"
fi

