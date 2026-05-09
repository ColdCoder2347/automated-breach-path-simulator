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


DEFAULT_REMEDIATION = {
    "title": "Reduce exploitability of attack path",
    "action": (
        "Review this attack edge, remove unnecessary trust, add detection coverage, "
        "and introduce compensating controls where possible."
    ),
    "control": "Security hardening",
    "effort": "medium",
    "cost": "medium",
    "owner": "Security Engineering",
}

FALLBACK_RULES = [
    {
        "keywords": ["mfa", "vpn"],
        "title": "Enforce MFA and conditional access",
        "action": "Require phishing-resistant MFA, device posture checks, and impossible-travel alerts for remote access.",
        "control": "Identity and access management",
        "effort": "medium",
        "cost": "medium",
        "owner": "Identity Team",
    },
    {
        "keywords": ["credential", "password", "token", "secret", "connection string"],
        "title": "Harden credential exposure and rotation",
        "action": "Rotate exposed secrets, move credentials into a managed vault, and alert on future secret exposure.",
        "control": "Secrets management",
        "effort": "medium",
        "cost": "low",
        "owner": "Security Engineering",
    },
    {
        "keywords": ["admin", "privileged", "domain admin", "group nesting"],
        "title": "Reduce privileged access blast radius",
        "action": "Remove standing privilege, enforce just-in-time access, and review nested admin group membership.",
        "control": "Privileged access management",
        "effort": "high",
        "cost": "medium",
        "owner": "Identity Team",
    },
    {
        "keywords": ["rdp", "remote shell", "smb", "shared"],
        "title": "Restrict lateral movement route",
        "action": "Segment the route, restrict remote service access, and monitor administrative session creation.",
        "control": "Network segmentation",
        "effort": "medium",
        "cost": "medium",
        "owner": "Infrastructure Team",
    },
    {
        "keywords": ["edr", "disable", "policy"],
        "title": "Protect defensive tooling from abuse",
        "action": "Separate EDR administration roles, require approval for policy disablement, and alert on tamper actions.",
        "control": "Endpoint protection governance",
        "effort": "medium",
        "cost": "low",
        "owner": "SOC Team",
    },
    {
        "keywords": ["backup"],
        "title": "Isolate backup administration path",
        "action": "Separate backup credentials, restrict backup operator delegation, and test immutable recovery controls.",
        "control": "Backup resilience",
        "effort": "medium",
        "cost": "medium",
        "owner": "Infrastructure Team",
    },
]


def edge_key(left: str, right: str) -> str:
    return f"{left}->{right}"


def has_metadata(edge: dict[str, Any]) -> bool:
    return any(
        edge.get(field)
        for field in (
            "remediation_title",
            "remediation_action",
            "remediation_control",
            "remediation_effort",
            "remediation_cost",
            "remediation_owner",
            "remediation_priority",
        )
    )


def fallback_profile(edge: dict[str, Any]) -> dict[str, Any]:
    label = edge.get("label", "").lower()
    for rule in FALLBACK_RULES:
        if any(keyword in label for keyword in rule["keywords"]):
            return rule

    if edge.get("cvss", 0) >= 9:
        return {
            "title": "Patch or isolate critical exploit path",
            "action": "Patch the vulnerable component or isolate the route until compensating controls are in place.",
            "control": "Vulnerability management",
            "effort": "medium",
            "cost": "medium",
            "owner": "Infrastructure Team",
        }

    if edge.get("complexity", 1) <= 2:
        return {
            "title": "Increase attack complexity with segmentation",
            "action": "Add network segmentation, access control lists, and service-level allow lists for this route.",
            "control": "Network segmentation",
            "effort": "medium",
            "cost": "medium",
            "owner": "Infrastructure Team",
        }

    return DEFAULT_REMEDIATION


def remediation_profile(edge: dict[str, Any]) -> dict[str, Any]:
    fallback = fallback_profile(edge)
    return {
        "title": edge.get("remediation_title") or fallback["title"],
        "action": edge.get("remediation_action") or fallback["action"],
        "control": edge.get("remediation_control") or fallback["control"],
        "effort": edge.get("remediation_effort") or fallback["effort"],
        "cost": edge.get("remediation_cost") or fallback["cost"],
        "owner": edge.get("remediation_owner") or fallback["owner"],
        "metadata_priority": edge.get("remediation_priority"),
        "source": "metadata" if has_metadata(edge) else "rule-fallback",
    }


def priority_weight(edge: dict[str, Any]) -> int:
    metadata_priority = edge.get("remediation_priority")
    if metadata_priority:
        return 6 - int(metadata_priority)
    return 0


def estimated_risk_reduction(edge: dict[str, Any], affected_paths: int, avg_risk: float) -> float:
    metadata_boost = priority_weight(edge) * 3
    return round(
        min(
            55,
            (edge.get("cvss", 0) * 2.4)
            + (affected_paths * 4)
            + (avg_risk * 0.08)
            + metadata_boost,
        ),
        1,
    )


def recommendation_text(
    edge: dict[str, Any],
    source_label: str,
    target_label: str,
    profile: dict[str, Any],
) -> str:
    label = edge.get("label", "attack edge")
    return (
        f"{profile['action']} This addresses '{label}' between {source_label} "
        f"and {target_label}."
    )


def evidence_lines(
    edge: dict[str, Any],
    affected_paths: int,
    avg_risk: float,
    source_label: str,
    target_label: str,
) -> list[str]:
    evidence = [
        f"Affects {affected_paths} of the ranked attack paths.",
        f"Average risk of affected paths is {round(avg_risk, 1)}/100.",
        f"Edge CVSS is {edge.get('cvss', 0)} with movement complexity {edge.get('complexity', 0)}.",
        f"Attack route segment: {source_label} -> {target_label}.",
    ]
    if edge.get("mitre_id"):
        evidence.append(
            f"Mapped to {edge.get('mitre_tactic')}: {edge.get('mitre_technique')} ({edge.get('mitre_id')})."
        )
    return evidence


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
            priority_weight(item["edge"]),
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
        profile = remediation_profile(edge)

        recommendations.append(
            RemediationRecommendation(
                priority=priority,
                title=profile["title"],
                target_type="edge",
                target_id=edge_key(source, target),
                affected_paths=affected_paths,
                estimated_risk_reduction=estimated_risk_reduction(edge, affected_paths, avg_risk),
                recommendation=recommendation_text(edge, source_label, target_label, profile),
                control=profile["control"],
                effort=profile["effort"],
                cost=profile["cost"],
                owner=profile["owner"],
                evidence=evidence_lines(edge, affected_paths, avg_risk, source_label, target_label),
                source=profile["source"],
            )
        )

    return RemediationResponse(
        selected_entry=selected_entry,
        selected_critical_asset=selected_critical,
        baseline_highest_risk=round(baseline_highest, 1),
        recommendations=recommendations,
    )
