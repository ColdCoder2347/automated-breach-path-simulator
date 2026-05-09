from __future__ import annotations

from enum import Enum
from typing import Any

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
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    mitre_id: str | None = None
    remediation_title: str | None = None
    remediation_action: str | None = None
    remediation_control: str | None = None
    remediation_effort: str | None = None
    remediation_cost: str | None = None
    remediation_owner: str | None = None
    remediation_priority: int | None = Field(default=None, ge=1, le=5)


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
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    mitre_id: str | None = None


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


class TopPathsRequest(BaseModel):
    network: NetworkData
    entry_point: str | None = None
    critical_asset: str | None = None
    limit: int = Field(default=5, ge=1, le=25)


class PathSummary(BaseModel):
    rank: int
    path: list[str]
    steps: list[PathStep]
    risk_score: float
    total_weight: float
    hop_count: int
    mitre_chain: list[str]
    reason: str


class TopPathsResponse(BaseModel):
    entry_points: list[str]
    critical_assets: list[str]
    selected_entry: str | None
    selected_critical_asset: str | None
    paths: list[PathSummary]


class RemediationRequest(BaseModel):
    network: NetworkData
    entry_point: str | None = None
    critical_asset: str | None = None
    limit: int = Field(default=5, ge=1, le=25)


class RemediationRecommendation(BaseModel):
    priority: int
    title: str
    target_type: str
    target_id: str
    affected_paths: int
    estimated_risk_reduction: float
    recommendation: str
    control: str
    effort: str
    cost: str
    owner: str
    evidence: list[str]
    source: str


class RemediationResponse(BaseModel):
    selected_entry: str | None
    selected_critical_asset: str | None
    baseline_highest_risk: float
    recommendations: list[RemediationRecommendation]


class TopologyValidationIssue(BaseModel):
    severity: str
    code: str
    message: str
    target: str | None = None


class TopologyValidationResponse(BaseModel):
    valid: bool
    errors: list[TopologyValidationIssue]
    warnings: list[TopologyValidationIssue]
    summary: dict[str, int]
