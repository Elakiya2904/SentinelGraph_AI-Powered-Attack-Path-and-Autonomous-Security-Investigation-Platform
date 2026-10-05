# SentinelGraph Safe Lab Demo Trigger (PowerShell)
# Expected flow:
# .\demo.ps1 -> simulated attack -> victim log -> detector -> SentinelGraph /alerts -> terminal display -> dashboard investigation

$ErrorActionPreference = "Continue"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  SENTINELGRAPH DOCKER-BASED DEMO TRIGGER" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# Step 1: Verify Docker engine is running
Write-Host "[1/5] Checking Docker daemon status..." -ForegroundColor Yellow
try {
    $dockerInfo = docker info 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "[!] Error: Docker daemon is not running or unreachable. Please start Docker Desktop and retry."
        exit 1
    }
} catch {
    Write-Error "[!] Error: Could not check Docker status: $_"
    exit 1
}
Write-Host "      Docker daemon is active." -ForegroundColor Green

# Step 2: Start required services: platform, victim, detector
Write-Host "[2/5] Ensuring required lab services are running..." -ForegroundColor Yellow
$null = docker compose --progress=plain up -d platform victim detector 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "[!] Error: Failed to start required Docker Compose services."
    exit 1
}

# Step 3: Wait for platform webhook
Write-Host "[3/5] Checking SentinelGraph platform webhook (http://127.0.0.1:8000/health)..." -ForegroundColor Yellow
$ready = $false
for ($i = 1; $i -le 30; $i++) {
    try {
        $res = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -Method Get -TimeoutSec 2 -ErrorAction SilentlyContinue
        if ($res -and $res.status -eq "ok") {
            $ready = $true
            break
        }
    } catch {
        # Retry until timeout
    }
    Start-Sleep -Seconds 1
}

if (-not $ready) {
    Write-Warning "[!] Error: SentinelGraph platform service failed to become ready within 30 seconds."
    Write-Host "    Recent platform logs:"
    docker compose logs platform --tail 25
    exit 1
}
Write-Host "      Platform is online and listening for detector webhooks." -ForegroundColor Green

# Step 4: Run the simulated attack strictly inside the isolated Docker network
Write-Host "`n[4/5] Executing simulated attack scenario against victim:2222..." -ForegroundColor Yellow
docker compose --progress=plain --profile demo run --rm attacker
if ($LASTEXITCODE -ne 0) {
    Write-Error "[!] Error: Failed to run simulated attacker container."
    exit 1
}

# Step 5: Wait for detector to tail logs and post alerts
Write-Host "[5/5] Waiting for detector to post normalized alerts to SentinelGraph..." -ForegroundColor Yellow
Start-Sleep -Seconds 2

try {
    $alertsData = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/alerts" -Method Get
    $invData = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/investigation/current" -Method Get

    $alerts = $alertsData.alerts
    $queueDepth = $alertsData.queue_depth

    if (-not $alerts -or $alerts.Count -eq 0) {
        Write-Warning "[!] Warning: No alerts found in SentinelGraph queue."
        exit 1
    }

    Write-Host "`n=================================================================" -ForegroundColor Cyan
    Write-Host "  GENERATED ALERTS & PIPELINE VERIFICATION" -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host "Total Alerts in Queue: $queueDepth" -ForegroundColor White
    Write-Host "-----------------------------------------------------------------"

    $displayCount = [Math]::Min(3, $alerts.Count)
    for ($idx = 0; $idx -lt $displayCount; $idx++) {
        $a = $alerts[$idx]
        Write-Host "[Alert $($idx + 1)]" -ForegroundColor Green
        Write-Host "  Alert ID:          $($a.alert_id)"
        Write-Host "  Source Host:       $($a.source_host)"
        Write-Host "  Rule Triggered:    $($a.rule)"
        Write-Host "  Severity:          $($a.severity)/10"
        Write-Host "  Timestamp:         $($a.timestamp)"
        Write-Host "  Detector:          $($a.detector)"
        Write-Host "  Status:            $($a.status)"
        Write-Host "  Raw Log Reference: $($a.raw_log_reference)"
        Write-Host "-----------------------------------------------------------------"
    }

    if ($invData.run_id) {
        Write-Host "INVESTIGATION TRIGGERED AUTOMATICALLY:" -ForegroundColor Magenta
        Write-Host "  Run ID:            $($invData.run_id)"
        Write-Host "  Status:            $($invData.status)"
        $verdict = $invData.verdict
        if ($verdict) {
            $conf = [Math]::Round($verdict.confidence * 100)
            $cov = [Math]::Round($verdict.evidence_coverage * 100)
            Write-Host "  Verdict:           $($verdict.state) ($conf% confidence)"
            Write-Host "  Evidence Coverage: $cov%"
            Write-Host "  Action (Gated):    $($verdict.recommended_action)"
        }
        Write-Host "-----------------------------------------------------------------"
    }

    Write-Host "`nDemo flow completed successfully:" -ForegroundColor Green
    Write-Host "  .\demo.ps1 -> simulated attack -> victim log -> detector -> SentinelGraph /alerts"
    Write-Host "`nNext steps:" -ForegroundColor Cyan
    Write-Host "  - Open the live SOC dashboard: http://localhost:3000"
    Write-Host "  - To stop the lab: docker compose down -v`n"

} catch {
    Write-Error "[!] Error fetching/formatting alerts: $_"
    exit 1
}
