from backend.app.graph.model import SyntheticLab
from backend.app.prediction import AttackPredictor
from backend.app.simulation import WhatIfRequest, WhatIfSimulator


def test_patch_simulation_removes_paths_without_mutating_baseline() -> None:
    lab = SyntheticLab()
    simulator = WhatIfSimulator(lab)
    baseline_paths = len(lab.attack_paths())
    result = simulator.simulate(WhatIfRequest(action="patch_vulnerability", node_id="web-portal", vulnerability_id="CVE-2021-44228"))
    assert result["status"] == "preview"
    assert result["baseline_mutated"] is False
    assert result["after"]["path_count"] < baseline_paths
    assert result["removed_paths"]
    assert len(lab.attack_paths()) == baseline_paths


def test_approval_applies_only_the_selected_graph_copy() -> None:
    lab = SyntheticLab()
    simulator = WhatIfSimulator(lab)
    result = simulator.simulate(WhatIfRequest(action="remove_edge", source="app-server", target="secrets-vault"))
    approved = simulator.approve(result["simulation_id"])
    assert approved["status"] == "approved"
    assert approved["baseline_mutated"] is True
    assert not lab.graph.has_edge("app-server", "secrets-vault")


def test_prediction_returns_top_three_with_prd_formula_components() -> None:
    prediction = AttackPredictor(SyntheticLab()).predict("victim")
    assert prediction["compromised_node"] == "vpn-bastion"
    assert len(prediction["candidates"]) == 3
    assert prediction["weights"] == {"exploitability": 0.4, "privilege_gain": 0.3, "proximity_to_crown_jewel": 0.3}
    for candidate in prediction["candidates"]:
        components = candidate["components"]
        assert all(0 <= value <= 1 for value in components.values())
        expected = round(0.4 * components["exploitability"] + 0.3 * components["privilege_gain"] + 0.3 * components["proximity_to_crown_jewel"], 3)
        assert candidate["score"] == expected


def test_close_port_simulation_removes_only_matching_port_edges() -> None:
    lab = SyntheticLab()
    simulator = WhatIfSimulator(lab)
    baseline_paths = len(lab.attack_paths())
    result = simulator.simulate(WhatIfRequest(action="close_port", port=8080, source="vpn-bastion", target="web-portal"))
    assert result["status"] == "preview"
    assert result["after"]["path_count"] < baseline_paths
    assert result["removed_paths"]
    assert lab.graph.has_edge("vpn-bastion", "web-portal")
    assert lab.graph.edges["vpn-bastion", "web-portal"]["port"] == 8080


def test_revoke_role_simulation_removes_role_access_without_mutating_baseline() -> None:
    lab = SyntheticLab()
    simulator = WhatIfSimulator(lab)
    baseline_paths = len(lab.attack_paths())
    result = simulator.simulate(WhatIfRequest(action="revoke_role", node_id="admin-role"))
    assert result["status"] == "preview"
    assert result["after"]["path_count"] < baseline_paths
    assert result["removed_paths"]
    assert "admin-role" in lab.graph.nodes
    assert len(lab.attack_paths()) == baseline_paths
