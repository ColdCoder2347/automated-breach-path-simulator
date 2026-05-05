from __future__ import annotations

import base64
import io
import json
from enum import Enum
from typing import Any

import networkx as nx
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


class Algorithm(str, Enum):
    bfs = "bfs"
    dfs = "dfs"
    dijkstra = "dijkstra"


class Node(BaseModel):
    id: str
    label: str
    type: str = "server"
    asset_value: float = Field(default=5, ge=0, le=10)


class Edge(BaseModel):
    source: str
    target: str
    label: str = "connection"
    cvss: float = Field(default=5, ge=0, le=10)
    complexity: float = Field(default=2, ge=1, le=10)


class NetworkData(BaseModel):
    nodes: list[Node]
    edges: list[Edge]


class AnalyzeRequest(BaseModel):
    network: NetworkData
    algorithm: Algorithm = Algorithm.dijkstra
    entry_point: str | None = None
    critical_asset: str | None = None


class PathStep(BaseModel):
    index: int
    node_id: str
    label: str
    type: str
    edge_label: str | None = None
    cvss: float | None = None
    complexity: float | None = None


class AnalyzeResponse(BaseModel):
    algorithm: Algorithm
    entry_points: list[str]
    critical_assets: list[str]
    selected_entry: str | None
    selected_critical_asset: str | None
    path: list[str]
    steps: list[PathStep]
    risk_score: float
    findings: list[str]
    metrics: dict[str, Any]


app = FastAPI(title="Automated Breach Path Simulator API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


SAMPLE_NETWORK = NetworkData(
    nodes=[
        Node(id="internet", label="Internet Phishing", type="entry", asset_value=2),
        Node(id="vpn", label="VPN Gateway", type="entry", asset_value=4),
        Node(id="workstation", label="Finance Workstation", type="user", asset_value=5),
        Node(id="ad", label="Active Directory", type="server", asset_value=9),
        Node(id="files", label="File Server", type="server", asset_value=7),
        Node(id="db", label="Customer Database", type="critical", asset_value=10),
        Node(id="backup", label="Backup Vault", type="critical", asset_value=9),
    ],
    edges=[
        Edge(source="internet", target="workstation", label="Phishing macro", cvss=8.1, complexity=3),
        Edge(source="vpn", target="workstation", label="Leaked VPN credential", cvss=7.5, complexity=2),
        Edge(source="workstation", target="ad", label="Cached domain admin token", cvss=9.2, complexity=4),
        Edge(source="workstation", target="files", label="Open SMB share", cvss=6.4, complexity=2),
        Edge(source="ad", target="db", label="Privileged SQL group", cvss=9.8, complexity=3),
        Edge(source="files", target="backup", label="Reused backup password", cvss=8.6, complexity=2),
        Edge(source="ad", target="backup", label="Backup operator delegation", cvss=7.9, complexity=3),
    ],
)


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


def path_steps(graph: nx.DiGraph, path: list[str]) -> list[PathStep]:
    steps: list[PathStep] = []
    for index, node_id in enumerate(path):
        node = graph.nodes[node_id]
        edge_data = None
        if index > 0:
            edge_data = graph.edges[path[index - 1], node_id]
        steps.append(
            PathStep(
                index=index,
                node_id=node_id,
                label=node.get("label", node_id),
                type=node.get("type", "server"),
                edge_label=edge_data.get("label") if edge_data else None,
                cvss=edge_data.get("cvss") if edge_data else None,
                complexity=edge_data.get("complexity") if edge_data else None,
            )
        )
    return steps


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
            "total_edge_weight": round(sum(graph.edges[a, b]["weight"] for a, b in zip(path, path[1:])), 2) if path else 0,
        },
    )


def minimal_pdf(title: str, lines: list[str]) -> bytes:
    stream = io.BytesIO()
    objects: list[bytes] = []

    content_lines = ["BT", "/F1 18 Tf", "50 770 Td", f"({escape_pdf(title)}) Tj", "/F1 10 Tf", "0 -28 Td"]
    for line in lines:
        content_lines.append(f"({escape_pdf(line[:105])}) Tj")
        content_lines.append("0 -16 Td")
    content_lines.append("ET")
    content = "\n".join(content_lines).encode("latin-1", errors="replace")

    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objects.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    objects.append(f"<< /Length {len(content)} >>\nstream\n".encode() + content + b"\nendstream")

    stream.write(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(stream.tell())
        stream.write(f"{index} 0 obj\n".encode())
        stream.write(obj)
        stream.write(b"\nendobj\n")

    xref = stream.tell()
    stream.write(f"xref\n0 {len(objects) + 1}\n".encode())
    stream.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        stream.write(f"{offset:010d} 00000 n \n".encode())
    stream.write(f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode())
    return stream.getvalue()


def escape_pdf(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


@app.api_route("/health", methods=["GET", "HEAD"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/sample")
def sample() -> NetworkData:
    return SAMPLE_NETWORK


@app.post("/analyze")
def analyze(payload: AnalyzeRequest) -> AnalyzeResponse:
    return analyze_payload(payload)


@app.post("/report/json")
def report_json(payload: AnalyzeRequest) -> dict[str, Any]:
    analysis = analyze_payload(payload)
    return {"network": payload.network.model_dump(), "analysis": analysis.model_dump()}


@app.post("/report/pdf")
def report_pdf(payload: AnalyzeRequest) -> Response:
    analysis = analyze_payload(payload)
    lines = [
        f"Algorithm: {analysis.algorithm.value.upper()}",
        f"Entry point: {analysis.selected_entry}",
        f"Critical asset: {analysis.selected_critical_asset}",
        f"Risk score: {analysis.risk_score}/100",
        f"Path: {' -> '.join(analysis.path) if analysis.path else 'No path found'}",
        "",
        "Findings:",
        *analysis.findings,
        "",
        "Step-by-step path:",
        *[
            f"{step.index + 1}. {step.label} ({step.type})"
            + (f" via {step.edge_label}, CVSS {step.cvss}" if step.edge_label else "")
            for step in analysis.steps
        ],
    ]
    pdf = minimal_pdf("Automated Breach Path Report", lines)
    encoded_name = base64.urlsafe_b64encode(b"breach-path-report.pdf").decode()
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=breach-path-report.pdf; filename*=UTF-8''{encoded_name}"},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.app:app", host="127.0.0.1", port=8765, reload=True)
