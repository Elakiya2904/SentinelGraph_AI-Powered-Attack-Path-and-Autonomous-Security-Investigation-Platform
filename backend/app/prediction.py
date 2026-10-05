from __future__ import annotations

from typing import Any

import networkx as nx

from .graph.model import SyntheticLab


class AttackPredictor:
    WEIGHTS = {"exploitability": 0.4, "privilege_gain": 0.3, "proximity_to_crown_jewel": 0.3}

    def __init__(self, lab: SyntheticLab) -> None:
        self.lab = lab
        self.aliases = {"victim": "vpn-bastion"}

    def predict(self, source_host: str = "victim") -> dict[str, Any]:
        graph = self.lab.graph
        compromised_node = self.aliases.get(source_host, source_host)
        if compromised_node not in graph.nodes:
            return {"source_host": source_host, "compromised_node": None, "candidates": [], "formula": self._formula()}
        foothold_privilege = graph.nodes[compromised_node].get("privilege_level", 0)
        reachable = nx.descendants(graph, compromised_node)
        candidates = []
        for candidate in reachable:
            data = graph.nodes[candidate]
            if data.get("kind") in {"entry", "vulnerability"} or data.get("crown_jewel"):
                continue
            exploitability = self._exploitability(data)
            privilege_gain = max(0.0, min(1.0, (data.get("privilege_level", 0) - foothold_privilege) / 4))
            proximity = self._proximity(graph, candidate)
            score = (
                self.WEIGHTS["exploitability"] * exploitability
                + self.WEIGHTS["privilege_gain"] * privilege_gain
                + self.WEIGHTS["proximity_to_crown_jewel"] * proximity
            )
            candidates.append({
                "node_id": candidate,
                "label": data.get("label", candidate),
                "kind": data.get("kind", "unknown"),
                "score": round(score, 3),
                "score_percent": round(score * 100, 1),
                "components": {
                    "exploitability": round(exploitability, 3),
                    "privilege_gain": round(privilege_gain, 3),
                    "proximity_to_crown_jewel": round(proximity, 3),
                },
                "reasons": self._reasons(exploitability, privilege_gain, proximity, data),
                "likely_techniques": self._techniques(data),
            })
        candidates.sort(key=lambda item: item["score"], reverse=True)
        return {
            "source_host": source_host,
            "compromised_node": compromised_node,
            "foothold_privilege": foothold_privilege,
            "candidates": candidates[:3],
            "formula": self._formula(),
            "weights": self.WEIGHTS,
            "method": "graph-based, explainable ranking; no ML decisioning",
        }

    @staticmethod
    def _exploitability(data: dict[str, Any]) -> float:
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return 0.35
        scores = []
        for vuln in vulnerabilities:
            severity = float(vuln.get("severity", 0)) / 10
            epss = float(vuln.get("epss", 0))
            kev_bonus = 0.15 if vuln.get("kev") else 0.0
            scores.append(min(1.0, 0.55 * severity + 0.3 * epss + kev_bonus))
        return max(scores)

    def _proximity(self, graph: nx.DiGraph, candidate: str) -> float:
        distances = []
        for crown in self.lab.crown_jewels:
            try:
                distances.append(nx.shortest_path_length(graph, candidate, crown))
            except nx.NetworkXNoPath:
                continue
        return round(min(1.0, 1 / min(distances)) if distances else 0.0, 3)

    @staticmethod
    def _reasons(exploitability: float, privilege_gain: float, proximity: float, data: dict[str, Any]) -> list[str]:
        reasons = []
        if exploitability >= 0.7:
            reasons.append("high exploitability signal")
        if privilege_gain > 0:
            reasons.append("increases privilege over the foothold")
        if proximity >= 0.5:
            reasons.append("close to a crown jewel")
        if not reasons:
            reasons.append(f"reachable {data.get('kind', 'asset')} with a graph path")
        return reasons

    @staticmethod
    def _techniques(data: dict[str, Any]) -> list[dict[str, str]]:
        techniques = []
        if data.get("kind") == "role":
            techniques.append({"id": "T1078", "name": "Valid Accounts"})
        if data.get("kind") == "service":
            techniques.append({"id": "T1021", "name": "Remote Services"})
        if data.get("vulnerabilities"):
            techniques.append({"id": "T1190", "name": "Exploit Public-Facing Application"})
        return techniques or [{"id": "T1046", "name": "Network Service Scanning"}]

    @staticmethod
    def _formula() -> str:
        return "score(c) = 0.4 × exploitability(c) + 0.3 × privilege_gain(c) + 0.3 × proximity_to_crown_jewel(c)"
