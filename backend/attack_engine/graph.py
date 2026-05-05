from __future__ import annotations

import networkx as nx

from backend.attack_engine.schemas import NetworkData, Node, PathStep
from backend.attack_engine.mitre import infer_mitre_mapping


def build_graph(network: NetworkData) -> nx.DiGraph:
    graph = nx.DiGraph()
    for node in network.nodes:
        graph.add_node(node.id, **node.model_dump())

    for edge in network.edges:
        # Lower weight means easier attacker movement. High CVSS lowers the cost;
        # complexity raises it.
        exploitability = max(edge.cvss, 0.1)
        weight = round(edge.complexity + (10 - exploitability) / 2, 3)
        graph.add_edge(edge.source, edge.target, **edge.model_dump(), weight=weight)

    return graph


def node_ids_by_role(network: NetworkData, role: str) -> list[str]:
    return [node.id for node in network.nodes if node.type == role]


def choose_default(ids: list[str], fallback: list[Node]) -> str | None:
    if ids:
        return ids[0]
    return fallback[0].id if fallback else None


def path_steps(graph: nx.DiGraph, path: list[str]) -> list[PathStep]:
    steps: list[PathStep] = []
    for index, node_id in enumerate(path):
        node = graph.nodes[node_id]
        edge_data = None
        if index > 0:
            edge_data = graph.edges[path[index - 1], node_id]
        mapping = infer_mitre_mapping(edge_data) if edge_data else {}
        steps.append(
            PathStep(
                index=index,
                node_id=node_id,
                label=node.get("label", node_id),
                type=node.get("type", "server"),
                edge_label=edge_data.get("label") if edge_data else None,
                cvss=edge_data.get("cvss") if edge_data else None,
                complexity=edge_data.get("complexity") if edge_data else None,
                mitre_tactic=mapping.get("mitre_tactic"),
                mitre_technique=mapping.get("mitre_technique"),
                mitre_id=mapping.get("mitre_id"),
            )
        )
    return steps
