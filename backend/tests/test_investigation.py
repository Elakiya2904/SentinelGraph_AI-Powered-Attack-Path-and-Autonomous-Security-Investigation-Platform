import asyncio

from backend.app.graph.model import SyntheticLab
from backend.app.investigation import ToolGroundedInvestigator


def test_tools_return_evidence_for_each_fact_source() -> None:
    investigator = ToolGroundedInvestigator(SyntheticLab())
    logs = investigator.tools.query_logs("victim")
    graph = investigator.tools.query_graph("victim")
    cve = investigator.tools.lookup_cve("CVE-2024-3400")
    technique = investigator.tools.map_attack_technique("ssh_brute_force_failed_login")
    asset = investigator.tools.get_asset_context("victim")
    assert logs["evidence"] and graph["evidence"] and cve["evidence"] and technique["evidence"] and asset["evidence"]
    assert technique["facts"]["id"] == "T1110"
    assert graph["facts"]["graph_node_id"] == "vpn-bastion"


def test_unsupported_claims_are_removed() -> None:
    valid = ToolGroundedInvestigator.validate_claims(
        [
            {"claim": "supported", "evidence_ids": ["e-1"]},
            {"claim": "unsupported", "evidence_ids": ["missing"]},
            {"claim": "empty", "evidence_ids": []},
        ],
        {"e-1"},
    )
    assert [claim["claim"] for claim in valid] == ["supported"]


def test_investigation_emits_confirmed_evidence_backed_verdict() -> None:
    investigator = ToolGroundedInvestigator(SyntheticLab())
    events = []

    async def emit(event):
        events.append(event)

    alert = {
        "alert_id": "alert-test",
        "source_host": "victim",
        "rule": "ssh_success_after_failures",
        "severity": 9,
    }
    result = asyncio.run(investigator.run(alert, emit, "investigation-test"))
    verdict = result["verdict"]
    assert verdict["state"] == "confirmed attack"
    assert verdict["evidence_coverage"] == 1.0
    assert all(claim["evidence_ids"] for claim in verdict["claims"])
    assert any(event["kind"] == "tool_call" and event["tool"] == "lookup_cve" for event in events)
    assert events[-1]["kind"] == "verdict"
