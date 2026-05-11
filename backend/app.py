from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.attack_engine.analysis import analyze_payload
from backend.attack_engine.llm_attack_chain import build_llm_attack_chain_response
from backend.attack_engine.llm_remediation import build_llm_remediation_response
from backend.attack_engine.mitigation import build_mitigation_simulation_response
from backend.attack_engine.paths import build_top_paths_response
from backend.attack_engine.remediation import build_remediation_response
from backend.attack_engine.reporting import report_json_payload, report_pdf_response
from backend.attack_engine.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    LLMAttackChainRequest,
    LLMAttackChainResponse,
    LLMRemediationResponse,
    MitigationSimulationRequest,
    MitigationSimulationResponse,
    NetworkData,
    RemediationRequest,
    RemediationResponse,
    TopPathsRequest,
    TopPathsResponse,
    TopologyValidationResponse,
)
from backend.attack_engine.topology_routes import router as topology_router
from backend.attack_engine.validation import validate_topology


app = FastAPI(title="Automated Breach Path Simulator API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(topology_router)


@app.api_route("/health", methods=["GET", "HEAD"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze")
def analyze(payload: AnalyzeRequest) -> AnalyzeResponse:
    return analyze_payload(payload)


@app.post("/paths/top")
def top_paths(payload: TopPathsRequest) -> TopPathsResponse:
    return build_top_paths_response(payload)


@app.post("/remediation/recommend")
def remediation_recommend(payload: RemediationRequest) -> RemediationResponse:
    return build_remediation_response(payload)


@app.post("/remediation/llm")
def remediation_llm(payload: RemediationRequest) -> LLMRemediationResponse:
    return build_llm_remediation_response(payload)


@app.post("/attack-chain/llm")
def attack_chain_llm(payload: LLMAttackChainRequest) -> LLMAttackChainResponse:
    return build_llm_attack_chain_response(payload)


@app.post("/mitigation/simulate")
def mitigation_simulate(payload: MitigationSimulationRequest) -> MitigationSimulationResponse:
    return build_mitigation_simulation_response(payload)


@app.post("/validate-topology")
def validate_network_topology(payload: NetworkData) -> TopologyValidationResponse:
    return validate_topology(payload)


@app.post("/report/json")
def report_json(payload: AnalyzeRequest) -> dict[str, Any]:
    return report_json_payload(payload)


@app.post("/report/pdf")
def report_pdf(payload: AnalyzeRequest):
    return report_pdf_response(payload)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.app:app", host="127.0.0.1", port=8765, reload=True)
