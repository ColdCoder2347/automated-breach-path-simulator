from __future__ import annotations

from backend.attack_engine.schemas import (
    NetworkData,
    TopologyValidationIssue,
    TopologyValidationResponse,
)


VALID_NODE_TYPES = {"entry", "user", "server", "database", "critical"}


def issue(
    severity: str,
    code: str,
    message: str,
    target: str | None = None,
) -> TopologyValidationIssue:
    return TopologyValidationIssue(
        severity=severity,
        code=code,
        message=message,
        target=target,
    )


def validate_topology(network: NetworkData) -> TopologyValidationResponse:
    errors: list[TopologyValidationIssue] = []
    warnings: list[TopologyValidationIssue] = []
    node_ids = [node.id for node in network.nodes]
    unique_node_ids = set(node_ids)

    if not network.nodes:
        errors.append(issue("error", "NO_NODES", "Topology must contain at least one node."))

    if not network.edges:
        warnings.append(issue("warning", "NO_EDGES", "Topology has no attack edges."))

    if len(node_ids) != len(unique_node_ids):
        duplicates = sorted({node_id for node_id in node_ids if node_ids.count(node_id) > 1})
        for duplicate in duplicates:
            errors.append(
                issue(
                    "error",
                    "DUPLICATE_NODE_ID",
                    f"Duplicate node id found: {duplicate}.",
                    duplicate,
                )
            )

    entry_points = [node for node in network.nodes if node.type == "entry"]
    critical_assets = [node for node in network.nodes if node.type == "critical"]

    if not entry_points:
        errors.append(issue("error", "NO_ENTRY_POINTS", "Topology must contain at least one entry node."))

    if not critical_assets:
        errors.append(issue("error", "NO_CRITICAL_ASSETS", "Topology must contain at least one critical asset."))

    for node in network.nodes:
        if node.type not in VALID_NODE_TYPES:
            warnings.append(
                issue(
                    "warning",
                    "UNKNOWN_NODE_TYPE",
                    f"Node '{node.id}' uses unknown type '{node.type}'.",
                    node.id,
                )
            )

        if node.asset_value >= 9 and node.type != "critical":
            warnings.append(
                issue(
                    "warning",
                    "HIGH_VALUE_NOT_CRITICAL",
                    f"Node '{node.id}' has high asset value but is not marked critical.",
                    node.id,
                )
            )

    for edge in network.edges:
        edge_id = f"{edge.source}->{edge.target}"

        if edge.source not in unique_node_ids:
            errors.append(
                issue(
                    "error",
                    "MISSING_EDGE_SOURCE",
                    f"Edge '{edge_id}' references missing source node '{edge.source}'.",
                    edge_id,
                )
            )

        if edge.target not in unique_node_ids:
            errors.append(
                issue(
                    "error",
                    "MISSING_EDGE_TARGET",
                    f"Edge '{edge_id}' references missing target node '{edge.target}'.",
                    edge_id,
                )
            )

        if edge.source == edge.target:
            warnings.append(
                issue(
                    "warning",
                    "SELF_LOOP",
                    f"Edge '{edge_id}' points to the same node.",
                    edge_id,
                )
            )

        if edge.cvss >= 9:
            warnings.append(
                issue(
                    "warning",
                    "CRITICAL_CVSS_EDGE",
                    f"Edge '{edge_id}' has critical CVSS score {edge.cvss}.",
                    edge_id,
                )
            )

        if edge.complexity <= 1 and edge.cvss >= 8:
            warnings.append(
                issue(
                    "warning",
                    "LOW_COMPLEXITY_HIGH_IMPACT",
                    f"Edge '{edge_id}' is both easy to exploit and high impact.",
                    edge_id,
                )
            )

        if not edge.mitre_tactic and not edge.mitre_technique and not edge.mitre_id:
            warnings.append(
                issue(
                    "warning",
                    "MITRE_MAPPING_INFERRED",
                    f"Edge '{edge_id}' has no explicit MITRE mapping; the engine will infer one from its label.",
                    edge_id,
                )
            )

    connected_node_ids = {edge.source for edge in network.edges} | {edge.target for edge in network.edges}
    isolated_nodes = sorted(unique_node_ids - connected_node_ids)

    for node_id in isolated_nodes:
        warnings.append(
            issue(
                "warning",
                "ISOLATED_NODE",
                f"Node '{node_id}' is isolated and cannot participate in attack paths.",
                node_id,
            )
        )

    return TopologyValidationResponse(
        valid=not errors,
        errors=errors,
        warnings=warnings,
        summary={
            "nodes": len(network.nodes),
            "edges": len(network.edges),
            "entry_points": len(entry_points),
            "critical_assets": len(critical_assets),
            "errors": len(errors),
            "warnings": len(warnings),
        },
    )
