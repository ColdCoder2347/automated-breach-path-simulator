from __future__ import annotations

import networkx as nx

from backend.attack_engine.graph import choose_default, node_ids_by_role, path_steps
from backend.attack_engine.scoring import score_path
from backend.attack_engine.schemas import (
    Algorithm,
    PathSummary,
    TopPathsRequest,
    TopPathsResponse,
)


def compute_path(graph: nx.DiGraph, source: str, target: str, algorithm: Algorithm) -> list[str]:
    if source not in graph or target not in graph:
        return []

    try:
        if algorithm == Algorithm.bfs:
            return nx.shortest_path(graph, source=source, target=target)
        if algorithm == Algorithm.dfs:
            tree = nx.dfs_tree(graph, source=source)
            return nx.shortest_path(tree, source=source, target=target)
        return nx.dijkstra_path(graph, source=source, target=target, weight="weight")
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []


def compute_top_paths(
    graph: nx.DiGraph,
    source: str,
    target: str,
    limit: int = 5,
) -> list[list[str]]:
    if source not in graph or target not in graph:
        return []

    try:
        generator = nx.shortest_simple_paths(graph, source, target, weight="weight")
        return [path for _, path in zip(range(limit), generator)]
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []


def path_total_weight(graph: nx.DiGraph, path: list[str]) -> float:
    if len(path) < 2:
        return 0

    return round(
        sum(graph.edges[left, right]["weight"] for left, right in zip(path, path[1:])),
        2,
    )


def explain_path(graph: nx.DiGraph, path: list[str], risk_score: float) -> str:
    if not path:
        return "No reachable path was found."

    start = graph.nodes[path[0]].get("label", path[0])
    end = graph.nodes[path[-1]].get("label", path[-1])
    high_cvss_edges = [
        graph.edges[left, right]["label"]
        for left, right in zip(path, path[1:])
        if graph.edges[left, right].get("cvss", 0) >= 8
    ]

    if high_cvss_edges:
        return (
            f"This path reaches {end} from {start} through "
            f"{len(path) - 1} hops and contains high-severity chaining points: "
            f"{', '.join(high_cvss_edges)}. Risk score: {risk_score}/100."
        )

    return (
        f"This path reaches {end} from {start} through "
        f"{len(path) - 1} hops with moderate exploitability. "
        f"Risk score: {risk_score}/100."
    )


def build_top_paths_response(payload: TopPathsRequest) -> TopPathsResponse:
    from backend.attack_engine.graph import build_graph

    graph = build_graph(payload.network)
    entry_points = node_ids_by_role(payload.network, "entry")
    critical_assets = node_ids_by_role(payload.network, "critical")
    selected_entry = payload.entry_point or choose_default(entry_points, payload.network.nodes)
    selected_critical = payload.critical_asset or choose_default(
        critical_assets,
        payload.network.nodes[::-1],
    )
    raw_paths = (
        compute_top_paths(graph, selected_entry, selected_critical, payload.limit)
        if selected_entry and selected_critical
        else []
    )

    summaries = []
    for index, path in enumerate(raw_paths, start=1):
        risk_score = score_path(graph, path)
        summaries.append(
            PathSummary(
                rank=index,
                path=path,
                steps=path_steps(graph, path),
                risk_score=risk_score,
                total_weight=path_total_weight(graph, path),
                hop_count=max(len(path) - 1, 0),
                reason=explain_path(graph, path, risk_score),
            )
        )

    return TopPathsResponse(
        entry_points=entry_points,
        critical_assets=critical_assets,
        selected_entry=selected_entry,
        selected_critical_asset=selected_critical,
        paths=summaries,
    )
