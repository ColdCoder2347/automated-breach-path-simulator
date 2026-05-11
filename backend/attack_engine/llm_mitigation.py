from __future__ import annotations

import json
import urllib.error
from typing import Any

import networkx as nx

from backend.attack_engine.ollama_client import (
    OllamaGenerateError,
    call_ollama_generate,
    ollama_model,
    parse_llm_json,
)
from backend.attack_engine.schemas import MitigationEstimate, MitigationMode, NetworkData


def build_ai_mitigation_estimate(
    network: NetworkData,
    graph: nx.DiGraph,
    target_edge: str,
    mode: MitigationMode,
    baseline_paths: list[list[str]],
) -> MitigationEstimate:
    source, target = parse_edge_key(target_edge)
    if not graph.has_edge(source, target):
        return MitigationEstimate(
            provider="metadata_risk_model",
            generated_by_llm=False,
            confidence=0,
            cvss_after=0,
            complexity_after=10,
            weight_after=10,
            rationale="The selected edge was not found in the graph, so no AI mitigation estimate could be generated.",
            controls=[],
            assumptions=["Selected edge was missing from the uploaded topology."],
        )

    edge = dict(graph.edges[source, target])
    model = ollama_model("OLLAMA_MITIGATION_MODEL")
    prompt = build_prompt(network, graph, target_edge, mode, baseline_paths)

    try:
        raw_response = call_ollama_generate(model, prompt, num_predict=900)
        parsed = parse_llm_json(raw_response.get("response", ""))
        return estimate_from_llm(parsed, edge, model)
    except (OllamaGenerateError, urllib.error.URLError, TimeoutError, ValueError, KeyError, TypeError):
        return estimate_from_metadata(edge, graph.nodes[source], graph.nodes[target], mode, baseline_paths)


def estimate_from_llm(parsed: dict[str, Any], edge: dict[str, Any], model: str) -> MitigationEstimate:
    current_cvss = float(edge.get("cvss", 5))
    current_complexity = float(edge.get("complexity", 3))
    cvss_after = min(clamp_float(parsed.get("cvss_after"), 0, 10, current_cvss), current_cvss)
    complexity_after = max(clamp_float(parsed.get("complexity_after"), 1, 10, current_complexity), current_complexity)
    weight_after = calculate_weight(cvss_after, complexity_after)

    return MitigationEstimate(
        provider="ollama",
        model=model,
        generated_by_llm=True,
        confidence=clamp_float(parsed.get("confidence"), 0, 1, 0.65),
        cvss_after=cvss_after,
        complexity_after=complexity_after,
        weight_after=weight_after,
        rationale=str(parsed.get("rationale") or "Qwen estimated the mitigation impact from the supplied attack graph context."),
        controls=string_list(parsed.get("controls"), 5),
        assumptions=string_list(parsed.get("assumptions"), 5),
    )


def estimate_from_metadata(
    edge: dict[str, Any],
    source_node: dict[str, Any],
    target_node: dict[str, Any],
    mode: MitigationMode,
    baseline_paths: list[list[str]],
) -> MitigationEstimate:
    current_cvss = float(edge.get("cvss", 5))
    current_complexity = float(edge.get("complexity", 3))
    control_strength = infer_control_strength(edge, source_node, target_node, mode, baseline_paths)

    cvss_after = round(max(0.1, current_cvss * (1 - 0.55 * control_strength)), 1)
    complexity_after = round(min(10, current_complexity + 5.5 * control_strength), 1)

    return MitigationEstimate(
        provider="metadata_risk_model",
        generated_by_llm=False,
        confidence=round(0.5 + (control_strength * 0.25), 2),
        cvss_after=cvss_after,
        complexity_after=complexity_after,
        weight_after=calculate_weight(cvss_after, complexity_after),
        rationale=(
            "Ollama was unavailable, so the simulator estimated mitigation impact from edge severity, "
            "movement complexity, MITRE metadata, remediation metadata, asset criticality, and path frequency."
        ),
        controls=infer_controls(edge, mode),
        assumptions=[
            "The estimate assumes the selected control is implemented correctly.",
            "No compensating attacker technique is added unless it already exists in the graph.",
        ],
    )


def apply_estimate_to_edge(graph: nx.DiGraph, target_edge: str, estimate: MitigationEstimate) -> None:
    source, target = parse_edge_key(target_edge)
    if not graph.has_edge(source, target):
        return

    edge = graph.edges[source, target]
    edge["cvss"] = estimate.cvss_after
    edge["complexity"] = estimate.complexity_after
    edge["weight"] = estimate.weight_after
    edge["ai_mitigation_provider"] = estimate.provider
    edge["ai_mitigation_confidence"] = estimate.confidence


def build_prompt(
    network: NetworkData,
    graph: nx.DiGraph,
    target_edge: str,
    mode: MitigationMode,
    baseline_paths: list[list[str]],
) -> str:
    source, target = parse_edge_key(target_edge)
    edge = dict(graph.edges[source, target])
    ranked_paths = [
        {
            "rank": index,
            "path": path,
            "uses_target_edge": edge_in_path(path, source, target),
        }
        for index, path in enumerate(baseline_paths[:8], start=1)
    ]

    context = {
        "task": "Estimate post-mitigation exploitability for a breach path simulator.",
        "mode": mode.value,
        "target_edge": target_edge,
        "source_node": dict(graph.nodes[source]),
        "target_node": dict(graph.nodes[target]),
        "edge_before": edge,
        "ranked_paths": ranked_paths,
        "network_size": {
            "nodes": len(network.nodes),
            "edges": len(network.edges),
        },
        "required_output_schema": {
            "cvss_after": "number from 0 to 10",
            "complexity_after": "number from 1 to 10",
            "confidence": "number from 0 to 1",
            "rationale": "short reason for the estimate",
            "controls": ["control applied"],
            "assumptions": ["assumption"],
        },
    }

    return (
        "You are Qwen acting as a cybersecurity risk estimation model inside an Electron desktop breach simulator.\n"
        "Estimate realistic post-mitigation values using the supplied graph metadata, not generic advice.\n"
        "For block_edge, estimate the residual exploitability if the edge is controlled by segmentation or access removal.\n"
        "For weaken_edge, estimate the reduced CVSS-like exploitability and increased attacker complexity after hardening.\n"
        "Return ONLY valid JSON matching the requested schema. Do not include markdown or prose outside JSON.\n\n"
        f"{json.dumps(context, indent=2)}"
    )


def infer_control_strength(
    edge: dict[str, Any],
    source_node: dict[str, Any],
    target_node: dict[str, Any],
    mode: MitigationMode,
    baseline_paths: list[list[str]],
) -> float:
    severity = float(edge.get("cvss", 5)) / 10
    complexity = float(edge.get("complexity", 3)) / 10
    target_value = float(target_node.get("asset_value", 5)) / 10
    metadata_depth = sum(
        1
        for key in (
            "mitre_id",
            "mitre_tactic",
            "mitre_technique",
            "remediation_action",
            "remediation_control",
            "remediation_owner",
        )
        if edge.get(key)
    ) / 6
    path_frequency = min(1, edge_path_frequency(edge, baseline_paths))
    mode_boost = 0.18 if mode == MitigationMode.block_edge else 0

    score = (
        0.3 * severity
        + 0.18 * (1 - complexity)
        + 0.18 * target_value
        + 0.2 * metadata_depth
        + 0.14 * path_frequency
        + mode_boost
    )
    return max(0.25, min(score, 0.92))


def infer_controls(edge: dict[str, Any], mode: MitigationMode) -> list[str]:
    if edge.get("remediation_control"):
        return [str(edge["remediation_control"])]
    if mode == MitigationMode.block_edge:
        return ["network segmentation", "access path removal"]
    if edge.get("mitre_tactic") == "Credential Access":
        return ["credential rotation", "multi-factor authentication"]
    return ["hardening", "patching", "least privilege"]


def edge_path_frequency(edge: dict[str, Any], paths: list[list[str]]) -> float:
    source = edge.get("source")
    target = edge.get("target")
    if not source or not target or not paths:
        return 0
    return sum(1 for path in paths if edge_in_path(path, source, target)) / len(paths)


def edge_in_path(path: list[str], source: str, target: str) -> bool:
    return any(left == source and right == target for left, right in zip(path, path[1:]))


def calculate_weight(cvss: float, complexity: float) -> float:
    return round(complexity + (10 - cvss) / 2, 3)


def clamp_float(value: Any, minimum: float, maximum: float, default: float) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        numeric = float(default)
    return round(max(minimum, min(maximum, numeric)), 2)


def string_list(value: Any, limit: int) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item][:limit]


def parse_edge_key(target_edge: str) -> tuple[str, str]:
    if "->" not in target_edge:
        return "", ""
    source, target = target_edge.split("->", 1)
    return source.strip(), target.strip()
