from __future__ import annotations

from backend.attack_engine.graph import build_graph, choose_default, node_ids_by_role, path_steps
from backend.attack_engine.paths import compute_path, path_total_weight
from backend.attack_engine.scoring import build_findings, score_path
from backend.attack_engine.schemas import AnalyzeRequest, AnalyzeResponse


def analyze_payload(payload: AnalyzeRequest) -> AnalyzeResponse:
    graph = build_graph(payload.network)
    entry_points = node_ids_by_role(payload.network, "entry")
    critical_assets = node_ids_by_role(payload.network, "critical")
    selected_entry = payload.entry_point or choose_default(entry_points, payload.network.nodes)
    selected_critical = payload.critical_asset or choose_default(critical_assets, payload.network.nodes[::-1])
    path = compute_path(graph, selected_entry, selected_critical, payload.algorithm) if selected_entry and selected_critical else []
    risk_score = score_path(graph, path)

    return AnalyzeResponse(
        algorithm=payload.algorithm,
        entry_points=entry_points,
        critical_assets=critical_assets,
        selected_entry=selected_entry,
        selected_critical_asset=selected_critical,
        path=path,
        steps=path_steps(graph, path),
        risk_score=risk_score,
        findings=build_findings(graph, path, risk_score),
        metrics={
            "nodes": graph.number_of_nodes(),
            "edges": graph.number_of_edges(),
            "path_length": max(len(path) - 1, 0),
            "total_edge_weight": path_total_weight(graph, path),
        },
    )
