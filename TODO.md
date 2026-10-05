# SentinelGraph TODO

## Phase 1 — Lab graph

Build a synthetic environment containing hosts/containers, services and ports, users, IAM-style roles, vulnerabilities, network links, entry points, and crown jewels. Store them as NetworkX nodes and edges using `CAN_REACH`, `HAS_VULN`, `CAN_ASSUME`, and `HAS_ACCESS_TO`. Enumerate attack paths from every entry point to every crown jewel. Rank nodes and edges by path coverage, using betweenness centrality as a supporting tie-breaker, and show why each is a choke point. Compute and display a transparent 0–100 aggregate risk score. Render the graph interactively with attack paths highlighted.

**Gate:** complete. The graph screen renders the synthetic lab, paths, crown jewels, entry points, top choke points, and risk score before alerting is enabled.

## Phase 2 — Real local alert pipeline

Expose FastAPI `POST /alerts` accepting timestamp, source host, rule, severity, and raw log reference. Normalize and queue alerts, add Docker Compose attacker/victim/detector lab services, and provide a safe local-only demo script. The detector must post alerts to the webhook; if a Falco/Wazuh daemon is not viable, explicitly label the fallback detector as simulated.

**Gate:** implementation complete. Docker execution remains to be run on a Docker-enabled machine; the safe scripted attack, normalized webhook, queue, history, SSE stream, and internal Compose network are in place.

## Phase 3 — Evidence-grounded investigation

Implement a ReAct-style investigation loop with `query_logs`, `query_graph`, `lookup_cve`, `map_attack_technique`, and `get_asset_context`. Stream tool calls and results to the UI. Every verdict claim must carry evidence, unsupported claims must be removed or flagged, confidence must come from evidence counts and cross-tool agreement, and the agent must only recommend actions for human approval.

**Gate:** complete. A live investigation shows failed logins, success, T1110 mapping, evidence-backed verdict, timeline, and recommendation; claims have 100% evidence coverage and actions remain human-gated.

## Phase 4 — React dashboard

Build four navigable screens: Attack Graph, Top Risks, Investigation, and What-if. Use React and Cytoscape.js with light-colored boxes and dark text. Include a real-versus-simulated status strip and stream investigation events without a reload.

**Gate:** complete. Attack Graph, Top Risks, Investigation, and What-if are navigable, use light surfaces with dark text, and are populated from live graph/alert/investigation state; What-if is a read-only preview until Phase 5.

## Phase 5 — What-if simulation

Allow a user to patch a vulnerability, close a port, revoke a role, or remove an edge on a graph copy. Recompute paths and risk, show removed paths and before/after risk, and require explicit human approval before applying any demo graph/lab update.

**Gate:** complete. Graph-copy simulation supports patching a vulnerability, closing a port, revoking a role, or removing an edge; before/after paths and risk are shown, and explicit approval is required before changing the demo baseline.

## Phase 6 — Attack prediction and evidence polish

From a compromised node, rank reachable next hops with `0.4 * exploitability + 0.3 * privilege_gain + 0.3 * proximity_to_crown_jewel`, show all components and the top three, and make the LLM explanatory only. Add a recorded backup demo, evidence coverage, and clear real/simulated labeling.

**Gate:** complete. The What-if workspace shows three transparent graph-based predictions with the 0.4/0.3/0.3 score components and optional ATT&CK technique mappings.
