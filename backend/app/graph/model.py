from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import networkx as nx


@dataclass(frozen=True)
class AttackPath:
    path_id: str
    entry_point: str
    crown_jewel: str
    nodes: list[str]
    edges: list[dict[str, str]]
    weakness_ids: list[str]
    likelihood: float


class SyntheticLab:
    """Deterministic, explainable attack graph for the isolated SentinelGraph demo."""

    def __init__(self) -> None:
        self.graph = nx.DiGraph()
        self._build()

    def _add_node(self, node_id: str, **metadata: Any) -> None:
        self.graph.add_node(node_id, **metadata)

    def _add_edge(self, source: str, target: str, edge_type: str, **metadata: Any) -> None:
        self.graph.add_edge(source, target, edge_type=edge_type, **metadata)

    def _build(self) -> None:
        self._add_node(
            "internet",
            kind="entry",
            label="Internet",
            entry_point=True,
            crown_jewel=False,
            privilege_level=0,
            description="External perimeter boundary representing untrusted ingress.",
        )
        self._add_node(
            "edge-gateway",
            kind="host",
            label="Edge Gateway (gw-ext-01)",
            entry_point=False,
            crown_jewel=False,
            privilege_level=1,
            services=["https:443", "ssh:22"],
            description="Public-facing reverse proxy and ingress traffic routing gateway.",
        )
        self._add_node(
            "vpn-bastion",
            kind="host",
            label="VPN Bastion (vpn-gw-01)",
            entry_point=False,
            crown_jewel=False,
            privilege_level=2,
            services=["ssh:22"],
            vulnerabilities=[{"id": "CVE-2024-3400", "severity": 9.8, "epss": 0.91, "kev": True}],
            description="Perimeter VPN bastion running PAN-OS with vulnerability CVE-2024-3400.",
        )
        self._add_node(
            "intern-laptop",
            kind="host",
            label="Workstation ws-corp-042",
            entry_point=False,
            crown_jewel=False,
            privilege_level=1,
            services=["smb:445", "ssh:22"],
            vulnerabilities=[{"id": "CVE-2023-23397", "severity": 9.8, "epss": 0.72, "kev": True}],
            description="Enterprise staff workstation with cached domain credentials (CVE-2023-23397).",
        )
        self._add_node(
            "corp-user",
            kind="user",
            label="corp\\analyst",
            entry_point=False,
            crown_jewel=False,
            privilege_level=1,
            description="Domain user identity (corp\\analyst) assigned to workstation.",
        )
        self._add_node(
            "web-portal",
            kind="service",
            label="Customer Web Portal",
            entry_point=False,
            crown_jewel=False,
            privilege_level=2,
            services=["http:8080"],
            vulnerabilities=[{"id": "CVE-2021-44228", "severity": 10.0, "epss": 0.94, "kev": True}],
            description="Production web portal running Log4j core with vulnerability CVE-2021-44228.",
        )
        self._add_node(
            "admin-role",
            kind="role",
            label="IAM App Admin Role",
            entry_point=False,
            crown_jewel=False,
            privilege_level=3,
            description="High-privilege IAM administration role across application cluster.",
        )
        self._add_node(
            "app-server",
            kind="host",
            label="Application Cluster Server",
            entry_point=False,
            crown_jewel=False,
            privilege_level=3,
            services=["http:8080", "ssh:22"],
            description="Core backend application cluster and data routing junction.",
        )
        self._add_node(
            "backup-service",
            kind="service",
            label="Enterprise Backup Service",
            entry_point=False,
            crown_jewel=False,
            privilege_level=3,
            services=["https:8443"],
            vulnerabilities=[{"id": "CVE-2024-3094", "severity": 10.0, "epss": 0.62, "kev": False}],
            description="Automated disaster-recovery backup service with database access (CVE-2024-3094).",
        )
        self._add_node(
            "prod-db",
            kind="crown",
            label="Production Database (PostgreSQL)",
            entry_point=False,
            crown_jewel=True,
            privilege_level=4,
            services=["postgres:5432"],
            description="Primary PostgreSQL database cluster hosting customer accounts and financial records.",
        )
        self._add_node(
            "secrets-vault",
            kind="crown",
            label="Enterprise Vault (HashiCorp)",
            entry_point=False,
            crown_jewel=True,
            privilege_level=4,
            services=["vault:8200"],
            description="Enterprise HashiCorp Vault cluster hosting signing keys and cloud master credentials.",
        )

        self._add_edge("internet", "edge-gateway", "CAN_REACH", port=443)
        self._add_edge("edge-gateway", "vpn-bastion", "CAN_REACH", port=22)
        self._add_edge("edge-gateway", "intern-laptop", "CAN_REACH", port=445)
        self._add_edge("vpn-bastion", "web-portal", "CAN_REACH", port=8080)
        self._add_edge("vpn-bastion", "admin-role", "CAN_ASSUME", reason="CVE-2024-3400")
        self._add_edge("corp-user", "intern-laptop", "HAS_ACCESS_TO", reason="primary workstation")
        self._add_edge("intern-laptop", "corp-user", "CAN_ASSUME", reason="CVE-2023-23397")
        self._add_edge("intern-laptop", "web-portal", "CAN_REACH", port=8080)
        self._add_edge("intern-laptop", "admin-role", "CAN_ASSUME", reason="captured session token")
        self._add_edge("web-portal", "admin-role", "CAN_ASSUME", reason="CVE-2021-44228")
        self._add_edge("admin-role", "app-server", "HAS_ACCESS_TO", reason="IAM policy app-admin")
        self._add_edge("web-portal", "app-server", "HAS_ACCESS_TO", reason="service network policy")
        self._add_edge("app-server", "prod-db", "HAS_ACCESS_TO", port=5432)
        self._add_edge("app-server", "secrets-vault", "HAS_ACCESS_TO", port=8200)
        self._add_edge("app-server", "backup-service", "HAS_ACCESS_TO", port=8443)
        self._add_edge("backup-service", "prod-db", "HAS_ACCESS_TO", reason="backup replication")
        self._add_edge("admin-role", "secrets-vault", "HAS_ACCESS_TO", reason="deployment read policy")
        self._materialize_vulnerabilities()

    def _materialize_vulnerabilities(self) -> None:
        """Represent each weakness as a first-class node for graph queries."""
        for host_id, host_data in list(self.graph.nodes(data=True)):
            for vulnerability in host_data.get("vulnerabilities", []):
                vulnerability_id = vulnerability["id"]
                node_id = f"vuln-{host_id}-{vulnerability_id.lower()}"
                self._add_node(
                    node_id,
                    kind="vulnerability",
                    label=vulnerability_id,
                    vulnerability_id=vulnerability_id,
                    severity=vulnerability.get("severity", 0),
                    epss=vulnerability.get("epss", 0),
                    kev=vulnerability.get("kev", False),
                    entry_point=False,
                    crown_jewel=False,
                    privilege_level=host_data.get("privilege_level", 0),
                    description=f"{vulnerability_id} on {host_data.get('label', host_id)}.",
                )
                self._add_edge(host_id, node_id, "HAS_VULN", vulnerability_id=vulnerability_id)

    @property
    def entry_points(self) -> list[str]:
        return [n for n, data in self.graph.nodes(data=True) if data.get("entry_point")]

    @property
    def crown_jewels(self) -> list[str]:
        return [n for n, data in self.graph.nodes(data=True) if data.get("crown_jewel")]

    def _path_likelihood(self, nodes: list[str]) -> float:
        values: list[float] = []
        for node in nodes:
            vulnerabilities = self.graph.nodes[node].get("vulnerabilities", [])
            if vulnerabilities:
                for vuln in vulnerabilities:
                    severity = float(vuln.get("severity", 0)) / 10
                    epss = float(vuln.get("epss", 0))
                    kev_bonus = 0.15 if vuln.get("kev") else 0.0
                    values.append(min(1.0, 0.55 * severity + 0.3 * epss + kev_bonus))
        if not values:
            return 0.52
        return round(sum(values) / len(values), 3)

    def attack_paths(self) -> list[AttackPath]:
        paths: list[AttackPath] = []
        for entry in self.entry_points:
            for crown in self.crown_jewels:
                for index, node_path in enumerate(nx.all_simple_paths(self.graph, entry, crown)):
                    edges = []
                    weakness_ids: list[str] = []
                    for source, target in zip(node_path, node_path[1:]):
                        edge = self.graph.edges[source, target]
                        edges.append({"source": source, "target": target, "type": edge["edge_type"]})
                        reason = edge.get("reason")
                        if reason and reason.startswith("CVE-"):
                            weakness_ids.append(reason)
                    for node in node_path:
                        weakness_ids.extend(v["id"] for v in self.graph.nodes[node].get("vulnerabilities", []))
                    paths.append(
                        AttackPath(
                            path_id=f"path-{len(paths) + 1:02d}",
                            entry_point=entry,
                            crown_jewel=crown,
                            nodes=node_path,
                            edges=edges,
                            weakness_ids=sorted(set(weakness_ids)),
                            likelihood=self._path_likelihood(node_path),
                        )
                    )
        return paths

    def choke_points(self) -> list[dict[str, Any]]:
        paths = self.attack_paths()
        total = len(paths)
        centrality = nx.betweenness_centrality(self.graph, normalized=True)
        ranked: list[dict[str, Any]] = []
        for node, data in self.graph.nodes(data=True):
            passing = [path.path_id for path in paths if node in path.nodes]
            if not passing:
                continue
            ranked.append(
                {
                    "id": node,
                    "label": data.get("label", node),
                    "kind": data.get("kind", "unknown"),
                    "path_count": len(passing),
                    "total_paths": total,
                    "coverage": round(len(passing) / total, 3) if total else 0,
                    "betweenness": round(centrality.get(node, 0), 3),
                    "path_ids": passing,
                    "weaknesses": sorted({w for path in paths if path.path_id in passing for w in path.weakness_ids}),
                    "reason": f"{len(passing)} of {total} attack paths pass through {data.get('label', node)}.",
                }
            )
        ranked.sort(key=lambda item: (item["coverage"], item["betweenness"]), reverse=True)
        return ranked

    def risk_score(self) -> dict[str, Any]:
        paths = self.attack_paths()
        total = len(paths)
        if not total:
            return {"score": 0, "path_count": 0, "average_path_likelihood": 0, "formula": "No entry-to-crown-jewel paths"}
        weighted_likelihood = sum(path.likelihood for path in paths) / total
        # Demo normalization: 24 weighted paths at full likelihood reaches 100.
        # This leaves room for a what-if fix to show a measurable before/after delta.
        score = min(100, round((total / 24) * weighted_likelihood * 100))
        return {
            "score": score,
            "path_count": total,
            "average_path_likelihood": round(weighted_likelihood, 3),
            "formula": "min(100, (paths / 24) × average weighted path likelihood × 100)",
        }

    def serialize(self) -> dict[str, Any]:
        paths = self.attack_paths()
        return {
            "nodes": [{"id": node, **data} for node, data in self.graph.nodes(data=True)],
            "edges": [
                {"id": f"edge-{source}-{target}", "source": source, "target": target, **data}
                for source, target, data in self.graph.edges(data=True)
            ],
            "paths": [path.__dict__ for path in paths],
            "entry_points": self.entry_points,
            "crown_jewels": self.crown_jewels,
            "choke_points": self.choke_points(),
            "risk": self.risk_score(),
            "metadata": {
                "environment": "enterprise-cloud-enclave",
                "graph_engine": "NetworkX Live",
                "air_gapped": True,
            },
        }
