from __future__ import annotations

import copy
import uuid
from typing import Any, Literal

import networkx as nx
from pydantic import BaseModel, Field

from .graph.model import SyntheticLab


class WhatIfRequest(BaseModel):
    action: Literal["patch_vulnerability", "close_port", "revoke_role", "remove_edge"]
    node_id: str | None = None
    vulnerability_id: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    source: str | None = None
    target: str | None = None


class WhatIfSimulator:
    def __init__(self, lab: SyntheticLab) -> None:
        self.lab = lab
        self.simulations: dict[str, dict[str, Any]] = {}

    def simulate(self, request: WhatIfRequest) -> dict[str, Any]:
        baseline = self.lab.serialize()
        simulated_lab = copy.copy(self.lab)
        simulated_lab.graph = copy.deepcopy(self.lab.graph)
        self._apply(simulated_lab.graph, request)
        after = simulated_lab.serialize()
        removed_paths = self._removed_paths(baseline["paths"], after["paths"])
        simulation_id = f"whatif-{uuid.uuid4().hex[:10]}"
        self.simulations[simulation_id] = {"graph": simulated_lab.graph, "request": request.model_dump(), "after": after}
        return {
            "simulation_id": simulation_id,
            "status": "preview",
            "request": request.model_dump(),
            "before": self._summary(baseline),
            "after": self._summary(after),
            "removed_paths": removed_paths,
            "risk_delta": after["risk"]["score"] - baseline["risk"]["score"],
            "path_delta": len(after["paths"]) - len(baseline["paths"]),
            "formula": after["risk"]["formula"],
            "approval_required": True,
            "baseline_mutated": False,
        }

    def approve(self, simulation_id: str) -> dict[str, Any]:
        simulation = self.simulations.get(simulation_id)
        if not simulation:
            raise KeyError(f"Unknown simulation: {simulation_id}")
        self.lab.graph = copy.deepcopy(simulation["graph"])
        applied = self.lab.serialize()
        return {
            "simulation_id": simulation_id,
            "status": "approved",
            "approval_required": False,
            "baseline_mutated": True,
            "graph": self._summary(applied),
        }

    @staticmethod
    def _summary(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "path_count": len(payload["paths"]),
            "risk": payload["risk"],
            "top_risks": payload["choke_points"][:5],
            "crown_jewels": payload["crown_jewels"],
        }

    @staticmethod
    def _removed_paths(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> list[dict[str, Any]]:
        after_signatures = {tuple(path["nodes"]) for path in after}
        return [path for path in before if tuple(path["nodes"]) not in after_signatures]

    @staticmethod
    def _apply(graph: nx.DiGraph, request: WhatIfRequest) -> None:
        if request.action == "patch_vulnerability":
            if not request.node_id or not request.vulnerability_id or request.node_id not in graph.nodes:
                raise ValueError("patch_vulnerability requires a valid node_id and vulnerability_id")
            node_data = graph.nodes[request.node_id]
            node_data["vulnerabilities"] = [
                vuln for vuln in node_data.get("vulnerabilities", []) if vuln.get("id") != request.vulnerability_id
            ]
            for source, target, data in list(graph.edges(data=True)):
                if source == request.node_id and data.get("edge_type") == "HAS_VULN" and data.get("vulnerability_id") == request.vulnerability_id:
                    graph.remove_edge(source, target)
                    if target in graph.nodes:
                        graph.remove_node(target)
            # In the lab model, exploitability is represented by the host's ability
            # to pivot through outgoing access/assumption edges. Patching the host
            # therefore closes those pivot edges on the copied graph.
            for source, target, data in list(graph.edges(data=True)):
                if source == request.node_id and data.get("edge_type") in {"CAN_REACH", "CAN_ASSUME", "HAS_ACCESS_TO"}:
                    graph.remove_edge(source, target)
        elif request.action == "close_port":
            if request.port is None:
                raise ValueError("close_port requires a port")
            for source, target, data in list(graph.edges(data=True)):
                if data.get("port") == request.port and (not request.source or source == request.source) and (not request.target or target == request.target):
                    graph.remove_edge(source, target)
        elif request.action == "revoke_role":
            if not request.node_id or request.node_id not in graph.nodes or graph.nodes[request.node_id].get("kind") != "role":
                raise ValueError("revoke_role requires a valid role node_id")
            graph.remove_node(request.node_id)
        elif request.action == "remove_edge":
            if not request.source or not request.target or not graph.has_edge(request.source, request.target):
                raise ValueError("remove_edge requires an existing source and target")
            graph.remove_edge(request.source, request.target)
