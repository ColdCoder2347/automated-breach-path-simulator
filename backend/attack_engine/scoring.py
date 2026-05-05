from __future__ import annotations

import networkx as nx


def score_path(graph: nx.DiGraph, path: list[str]) -> float:
    if len(path) < 2:
        return 0

    edge_scores = []
    for left, right in zip(path, path[1:]):
        edge = graph.edges[left, right]
        edge_scores.append((edge["cvss"] * 10) - (edge["complexity"] * 2))

    asset_value = graph.nodes[path[-1]].get("asset_value", 5) * 10
    complexity_discount = max(0, (len(path) - 2) * 4)
    raw_score = (sum(edge_scores) / len(edge_scores)) * 0.65 + asset_value * 0.35 - complexity_discount
    return round(max(0, min(raw_score, 100)), 1)


def build_findings(graph: nx.DiGraph, path: list[str], risk_score: float) -> list[str]:
    if not path:
        return ["No reachable attack path was found between the selected entry point and critical asset."]

    findings = [
        f"Most likely path traverses {len(path)} systems from {graph.nodes[path[0]]['label']} to {graph.nodes[path[-1]]['label']}.",
        f"Calculated path risk is {risk_score}/100 based on exploit severity, target value, and movement complexity.",
    ]
    severe_edges = [
        graph.edges[left, right]["label"]
        for left, right in zip(path, path[1:])
        if graph.edges[left, right]["cvss"] >= 8
    ]
    if severe_edges:
        findings.append("High-severity chaining points: " + ", ".join(severe_edges) + ".")
    return findings
