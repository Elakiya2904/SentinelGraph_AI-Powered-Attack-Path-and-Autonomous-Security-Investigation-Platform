from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from .alerts import AlertIn, AlertQueue
from .graph.model import SyntheticLab
from .investigation import InvestigationManager
from .prediction import AttackPredictor
from .simulation import WhatIfRequest, WhatIfSimulator

app = FastAPI(title="SentinelGraph API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

lab = SyntheticLab()
alert_queue = AlertQueue()
investigation_manager = InvestigationManager(lab)
what_if_simulator = WhatIfSimulator(lab)
attack_predictor = AttackPredictor(lab)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "phase": "5-simulation-prediction", "queue_depth": str(alert_queue.pending_count()), "investigation_status": investigation_manager.snapshot()["status"]}


@app.post("/alerts", status_code=202)
async def receive_alert(alert: AlertIn) -> dict:
    normalized = alert.normalized()
    await alert_queue.publish(normalized)
    run_id = investigation_manager.start(normalized)
    return {"status": "queued", "alert": normalized, "queue_depth": alert_queue.pending_count(), "investigation_run_id": run_id}


@app.get("/api/alerts")
def get_alerts() -> dict:
    return {"alerts": alert_queue.snapshot(), "queue_depth": alert_queue.pending_count()}


@app.get("/api/alerts/stream")
async def stream_alerts() -> StreamingResponse:
    subscriber = await alert_queue.subscribe()

    async def event_stream():
        try:
            yield "event: ready\ndata: {\"status\":\"connected\"}\n\n"
            while True:
                try:
                    alert = await asyncio.wait_for(subscriber.get(), timeout=20)
                    yield f"event: alert\ndata: {json.dumps(alert)}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        finally:
            await alert_queue.unsubscribe(subscriber)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/investigation/current")
def get_current_investigation() -> dict:
    return investigation_manager.snapshot()


@app.get("/api/investigation/stream")
async def stream_investigation() -> StreamingResponse:
    subscriber, backlog = await investigation_manager.subscribe()

    async def event_stream():
        try:
            for event in backlog:
                yield f"event: step\ndata: {json.dumps(event)}\n\n"
            yield "event: ready\ndata: {\"status\":\"connected\"}\n\n"
            while True:
                try:
                    event = await asyncio.wait_for(subscriber.get(), timeout=20)
                    yield f"event: step\ndata: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        finally:
            await investigation_manager.unsubscribe(subscriber)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/graph")
def get_graph() -> dict:
    return lab.serialize()


@app.get("/api/paths")
def get_paths() -> dict:
    payload = lab.serialize()
    return {"paths": payload["paths"], "count": len(payload["paths"]), "risk": payload["risk"]}


@app.get("/api/risks")
def get_risks() -> dict:
    payload = lab.serialize()
    return {"choke_points": payload["choke_points"], "risk": payload["risk"]}


@app.post("/api/what-if/simulate")
def simulate_what_if(request: WhatIfRequest) -> dict:
    try:
        return what_if_simulator.simulate(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/what-if/approve")
def approve_what_if(payload: dict[str, str]) -> dict:
    simulation_id = payload.get("simulation_id")
    if not simulation_id:
        raise HTTPException(status_code=400, detail="simulation_id is required")
    try:
        return what_if_simulator.approve(simulation_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/prediction")
def get_prediction(source_host: str = "victim") -> dict:
    return attack_predictor.predict(source_host)


@app.post("/api/demo/trigger")
async def trigger_demo_event(scenario: str = "ssh") -> dict:
    log_file_path = os.environ.get("VICTIM_LOG", "/logs/victim.log")
    ts = datetime.now(timezone.utc).isoformat()

    if scenario == "web":
        if os.path.exists(log_file_path):
            try:
                with open(log_file_path, "a", encoding="utf-8") as f:
                    f.write(f"{ts} WEB_REQUEST client=172.18.0.5 method=GET path=/login?user=admin' OR 1=1-- raw_path=/login?user=admin'%20OR%201=1--\n")
                    f.write(f"{ts} WEB_REQUEST client=172.18.0.5 method=GET path=/view?page=../../../../etc/passwd raw_path=/view?page=../../../../etc/passwd\n")
            except Exception:
                pass

        alerts_data = [
            {
                "source_host": "web-portal",
                "rule": "web_sqli_injection_attempt",
                "severity": 8,
                "raw_log_reference": f"victim.log:{ts} WEB_REQUEST client=172.18.0.5 method=GET path=/login?user=admin' OR 1=1--",
                "detector": "sentinelgraph-edr-agent",
                "source": "production-enclave",
                "raw_payload": {"src_ip": "172.18.0.5", "target_port": 8080, "attack_type": "sqli", "payload": "' OR 1=1"},
            },
            {
                "source_host": "web-portal",
                "rule": "web_path_traversal_attempt",
                "severity": 8,
                "raw_log_reference": f"victim.log:{ts} WEB_REQUEST client=172.18.0.5 method=GET path=/view?page=../../../../etc/passwd",
                "detector": "sentinelgraph-edr-agent",
                "source": "production-enclave",
                "raw_payload": {"src_ip": "172.18.0.5", "target_port": 8080, "attack_type": "traversal", "payload": "../"},
            },
        ]
    elif scenario == "aws":
        aws_ref = "aws:cloudtrail:failed-login:arn:aws:ec2:us-east-1:123456789012:instance/i-0a89bc44d12"
        alerts_data = [
            {
                "source_host": "vpn-bastion",
                "rule": "aws_guardduty_unauthorized_access",
                "severity": 9,
                "raw_log_reference": f"{aws_ref}:{ts} FailedLogin src=13.58.13.54 target=i-0a89bc44d12 attempts=3",
                "detector": "aws-guard-duty",
                "source": "aws-production",
                "raw_payload": {
                    "account_id": "123456789012",
                    "region": "us-east-1",
                    "resource": "arn:aws:ec2:us-east-1:123456789012:instance/i-0a89bc44d12",
                    "finding_type": "UnauthorizedAccess:EC2/SSHBruteForce",
                    "source_ip": "13.58.13.54",
                    "target_port": 22,
                    "attempt_count": 3,
                    "user": "admin",
                },
            }
        ]
    else:
        if os.path.exists(log_file_path):
            try:
                with open(log_file_path, "a", encoding="utf-8") as f:
                    f.write(f"{ts} AUTH_FAIL src=198.51.100.42 user=root service=ssh reason=invalid_credentials (attempt 1/3)\n")
                    f.write(f"{ts} AUTH_FAIL src=198.51.100.42 user=admin service=ssh reason=invalid_credentials (attempt 2/3)\n")
                    f.write(f"{ts} AUTH_FAIL src=198.51.100.42 user=demo service=ssh reason=invalid_credentials (attempt 3/3)\n")
            except Exception:
                pass

        alerts_data = [
            {
                "source_host": "victim",
                "rule": "ssh_brute_force_failed_login",
                "severity": 9,
                "raw_log_reference": f"victim.log:{ts} AUTH_FAIL src=198.51.100.42 user=demo service=ssh (3 consecutive failures)",
                "detector": "sentinelgraph-edr-agent",
                "source": "production-enclave",
                "raw_payload": {"src_ip": "198.51.100.42", "target_port": 22, "attempts": 3, "status": "3 auth failed"},
            }
        ]

    created = []
    for alert_dict in alerts_data:
        normalized = AlertIn(**alert_dict).normalized()
        await alert_queue.publish(normalized)
        run_id = investigation_manager.start(normalized)
        created.append({"alert_id": normalized["alert_id"], "run_id": run_id})
    return {"status": "triggered", "scenario": scenario, "alerts": created}


@app.post("/api/demo/reset")
async def reset_demo_state() -> dict:
    global alert_queue, investigation_manager, lab, what_if_simulator, attack_predictor
    lab = SyntheticLab()
    alert_queue = AlertQueue()
    investigation_manager = InvestigationManager(lab)
    what_if_simulator = WhatIfSimulator(lab)
    attack_predictor = AttackPredictor(lab)
    log_file_path = os.environ.get("VICTIM_LOG", "/logs/victim.log")
    if os.path.exists(log_file_path):
        try:
            with open(log_file_path, "w", encoding="utf-8") as f:
                f.write("")
        except Exception:
            pass
    return {"status": "reset", "queue_depth": 0}
