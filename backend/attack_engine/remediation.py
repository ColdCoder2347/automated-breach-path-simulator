from __future__ import annotations

from typing import Any

from backend.attack_engine.graph import build_graph, choose_default, node_ids_by_role
from backend.attack_engine.paths import compute_top_paths
from backend.attack_engine.scoring import score_path
from backend.attack_engine.schemas import (
    RemediationRecommendation,
    RemediationRequest,
    RemediationResponse,
)


def edge_key(left: str, right: str) -> str:
    return f"{left}->{right}"


def remediation_title(edge: dict[str, Any]) -> str:
    label = edge.get("label", "").lower()
    cvss = edge.get("cvss", 0)
    complexity = edge.get("complexity", 1)

    if "credential" in label or "password" in label or "token" in label:
        return "Harden credential exposure and rotation"
    if "mfa" in label or "vpn" in label:
        return "Enforce MFA and conditional access"
    if "admin" in label or "privileged" in label:
        return "Reduce privileged access blast radius"
    if cvss >= 9:
        return "Patch or isolate critical exploit path"
    if complexity <= 2:
        return "Increase attack complexity with segmentation"
    return "Reduce exploitability of attack path"


def remediation_text(edge: dict[str, Any], source_label: str, target_label: str) -> str:
    label = edge.get("label", "attack edge")
    return (
        f"Mitigate '{label}' between {source_label} and {target_label}. "
        "Recommended actions: remove unnecessary trust, rotate exposed secrets, "
        "enforce least privilege, add detection coverage, and introduce network "
        "segmentation where possible."
    )


def build_remediation_response(payload: RemediationRequest) -> RemediationResponse:
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
    baseline_risks = [score_path(graph, path) for path in raw_paths]
    baseline_highest = max(baseline_risks) if baseline_risks else 0
    edge_impact: dict[str, dict[str, Any]] = {}

    for path, risk in zip(raw_paths, baseline_risks):
        for left, right in zip(path, path[1:]):
            key = edge_key(left, right)
            edge = graph.edges[left, right]
            if key not in edge_impact:
                edge_impact[key] = {
                    "source": left,
                    "target": right,
                    "edge": edge,
                    "affected_paths": 0,
                    "risk_sum": 0.0,
                }
            edge_impact[key]["affected_paths"] += 1
            edge_impact[key]["risk_sum"] += risk

    ranked_edges = sorted(
        edge_impact.values(),
        key=lambda item: (
            item["affected_paths"],
            item["risk_sum"],
            item["edge"].get("cvss", 0),
        ),
        reverse=True,
    )
    recommendations: list[RemediationRecommendation] = []

    for priority, item in enumerate(ranked_edges[:5], start=1):
        source = item["source"]
        target = item["target"]
        edge = item["edge"]
        source_label = graph.nodes[source].get("label", source)
        target_label = graph.nodes[target].get("label", target)
        affected_paths = item["affected_paths"]
        avg_risk = item["risk_sum"] / affected_paths if affected_paths else 0
        estimated_reduction = round(
            min(
                45,
                (edge.get("cvss", 0) * 2.5)
                + (affected_paths * 4)
                + (avg_risk * 0.08),
            ),
            1,
        )
        recommendations.append(
            RemediationRecommendation(
                priority=priority,
                title=remediation_title(edge),
                target_type="edge",
                target_id=edge_key(source, target),
                affected_paths=affected_paths,
                estimated_risk_reduction=estimated_reduction,
                recommendation=remediation_text(edge, source_label, target_label),
            )
        )

    return RemediationResponse(
        selected_entry=selected_entry,
        selected_critical_asset=selected_critical,
        baseline_highest_risk=round(baseline_highest, 1),
        recommendations=recommendations,
    )
