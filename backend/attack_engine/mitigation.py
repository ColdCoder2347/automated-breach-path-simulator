from __future__ import annotations

from backend.attack_engine.graph import build_graph, choose_default, node_ids_by_role, path_steps
from backend.attack_engine.llm_mitigation import apply_estimate_to_edge, build_ai_mitigation_estimate
from backend.attack_engine.mitre import path_mitre_chain
from backend.attack_engine.paths import compute_top_paths, explain_path, path_total_weight
from backend.attack_engine.scoring import score_path
from backend.attack_engine.schemas import (
    MitigationMode,
    MitigationSimulationRequest,
    MitigationSimulationResponse,
    PathSummary,
)


def build_mitigation_simulation_response(
    payload: MitigationSimulationRequest,
) -> MitigationSimulationResponse:
    baseline_graph = build_graph(payload.network)
    mitigated_graph = build_graph(payload.network)
    entry_points = node_ids_by_role(payload.network, "entry")
    critical_assets = node_ids_by_role(payload.network, "critical")
    selected_entry = payload.entry_point or choose_default(entry_points, payload.network.nodes)
    selected_critical = payload.critical_asset or choose_default(critical_assets, payload.network.nodes[::-1])

    baseline_raw_paths = (
        compute_top_paths(baseline_graph, selected_entry, selected_critical, payload.limit)
        if selected_entry and selected_critical
        else []
    )

    mitigation_estimate = build_ai_mitigation_estimate(
        payload.network,
        baseline_graph,
        payload.target_edge,
        payload.mode,
        baseline_raw_paths,
    )

    apply_mitigation(mitigated_graph, payload.target_edge, payload.mode, mitigation_estimate)

    mitigated_raw_paths = (
        compute_top_paths(mitigated_graph, selected_entry, selected_critical, payload.limit)
        if selected_entry and selected_critical
        else []
    )

    baseline_paths = summarize_paths(baseline_graph, baseline_raw_paths)
    mitigated_paths = summarize_paths(mitigated_graph, mitigated_raw_paths)
    baseline_highest = highest_risk(baseline_paths)
    mitigated_highest = highest_risk(mitigated_paths)
    blocked_count = count_blocked_paths(baseline_raw_paths, mitigated_raw_paths)
    risk_reduction = round(max(baseline_highest - mitigated_highest, 0), 1)

    return MitigationSimulationResponse(
        target_edge=payload.target_edge,
        mode=payload.mode,
        estimate=mitigation_estimate,
        baseline_highest_risk=baseline_highest,
        mitigated_highest_risk=mitigated_highest,
        risk_reduction=risk_reduction,
        baseline_path_count=len(baseline_paths),
        mitigated_path_count=len(mitigated_paths),
        blocked_path_count=blocked_count,
        baseline_paths=baseline_paths,
        mitigated_paths=mitigated_paths,
        summary=build_summary(
            payload.target_edge,
            payload.mode,
            mitigation_estimate.rationale,
            risk_reduction,
            blocked_count,
            mitigated_paths,
        ),
    )


def apply_mitigation(graph, target_edge: str, mode: MitigationMode, mitigation_estimate) -> None:
    source, target = parse_edge_key(target_edge)

    if not graph.has_edge(source, target):
        return

    if mode == MitigationMode.block_edge:
        graph.remove_edge(source, target)
        return

    apply_estimate_to_edge(graph, target_edge, mitigation_estimate)


def parse_edge_key(target_edge: str) -> tuple[str, str]:
    if "->" not in target_edge:
        return "", ""

    source, target = target_edge.split("->", 1)
    return source.strip(), target.strip()


def summarize_paths(graph, paths: list[list[str]]) -> list[PathSummary]:
    summaries = []

    for index, path in enumerate(paths, start=1):
        risk_score = score_path(graph, path)
        summaries.append(
            PathSummary(
                rank=index,
                path=path,
                steps=path_steps(graph, path),
                risk_score=risk_score,
                total_weight=path_total_weight(graph, path),
                hop_count=max(len(path) - 1, 0),
                mitre_chain=path_mitre_chain(graph, path),
                reason=explain_path(graph, path, risk_score),
            )
        )

    return summaries


def highest_risk(paths: list[PathSummary]) -> float:
    if not paths:
        return 0
    return max(path.risk_score for path in paths)


def count_blocked_paths(baseline_paths: list[list[str]], mitigated_paths: list[list[str]]) -> int:
    mitigated = {tuple(path) for path in mitigated_paths}
    return sum(1 for path in baseline_paths if tuple(path) not in mitigated)


def build_summary(
    target_edge: str,
    mode: MitigationMode,
    rationale: str,
    risk_reduction: float,
    blocked_count: int,
    mitigated_paths: list[PathSummary],
) -> str:
    action = "blocking" if mode == MitigationMode.block_edge else "weakening"

    if not mitigated_paths:
        return (
            f"After {action} {target_edge}, no reachable ranked attack path remains "
            f"for the selected entry and critical asset. Estimated risk reduction is {risk_reduction}. "
            f"AI estimate: {rationale}"
        )

    return (
        f"After {action} {target_edge}, {blocked_count} ranked path(s) changed or disappeared. "
        f"The highest remaining path risk is {highest_risk(mitigated_paths)}/100, "
        f"for an estimated reduction of {risk_reduction}. AI estimate: {rationale}"
    )
