from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware

from backend.attack_engine.analysis import analyze_payload
from backend.attack_engine.paths import build_top_paths_response
from backend.attack_engine.remediation import build_remediation_response
from backend.attack_engine.reporting import report_json_payload, report_pdf_response
from backend.attack_engine.sample_data import SAMPLE_NETWORK
from backend.attack_engine.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    NetworkData,
    RemediationRequest,
    RemediationResponse,
    TopPathsRequest,
    TopPathsResponse,
)


app = FastAPI(title="Automated Breach Path Simulator API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.api_route("/health", methods=["GET", "HEAD"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/sample")
def sample() -> NetworkData:
    return SAMPLE_NETWORK


@app.post("/analyze")
def analyze(payload: AnalyzeRequest) -> AnalyzeResponse:
    return analyze_payload(payload)


@app.post("/paths/top")
def top_paths(payload: TopPathsRequest) -> TopPathsResponse:
    return build_top_paths_response(payload)


@app.post("/remediation/recommend")
def remediation_recommend(payload: RemediationRequest) -> RemediationResponse:
    return build_remediation_response(payload)


@app.post("/report/json")
def report_json(payload: AnalyzeRequest) -> dict[str, Any]:
    return report_json_payload(payload)


@app.post("/report/pdf")
def report_pdf(payload: AnalyzeRequest) -> Response:
    return report_pdf_response(payload)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.app:app", host="127.0.0.1", port=8765, reload=True)
