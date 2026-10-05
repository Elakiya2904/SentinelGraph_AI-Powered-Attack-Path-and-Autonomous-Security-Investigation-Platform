from backend.app.graph.model import SyntheticLab
from backend.app.main import app
from fastapi.testclient import TestClient


def test_lab_contains_entry_points_and_crown_jewels() -> None:
    lab = SyntheticLab()
    assert lab.entry_points == ["internet"]
    assert set(lab.crown_jewels) == {"prod-db", "secrets-vault"}
    edge_types = {data["edge_type"] for _, _, data in lab.graph.edges(data=True)}
    assert {"CAN_REACH", "HAS_VULN", "CAN_ASSUME", "HAS_ACCESS_TO"}.issubset(edge_types)


def test_paths_and_choke_points_are_explainable() -> None:
    lab = SyntheticLab()
    paths = lab.attack_paths()
    assert len(paths) >= 3
    assert all(path.path_id and path.nodes[0] == "internet" for path in paths)
    top = lab.choke_points()[0]
    assert top["path_count"] == top["total_paths"]
    assert top["reason"]


def test_risk_is_bounded_and_transparent() -> None:
    risk = SyntheticLab().risk_score()
    assert 0 <= risk["score"] <= 100
    assert risk["path_count"] > 0
    assert "average weighted path likelihood" in risk["formula"]


def test_alert_webhook_normalizes_and_queues_alert() -> None:
    client = TestClient(app)
    response = client.post(
        "/alerts",
        json={
            "source_host": "victim",
            "rule": "ssh_brute_force",
            "severity": 8,
            "raw_log_reference": "victim.log:12",
            "detector": "local-detector",
        },
    )
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "queued"
    assert body["alert"]["alert_id"].startswith("alert-")
    assert client.get("/api/alerts").json()["alerts"][0]["source_host"] == "victim"
