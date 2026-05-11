from __future__ import annotations

import json
import urllib.error
from typing import Any

from fastapi import HTTPException

from backend.attack_engine.ollama_client import (
    OllamaGenerateError,
    call_ollama_generate,
    ollama_model,
    parse_llm_json,
)
from backend.attack_engine.remediation import build_remediation_response
from backend.attack_engine.schemas import (
    LLMRemediationAction,
    LLMRemediationResponse,
    RemediationRequest,
)


def build_llm_remediation_response(payload: RemediationRequest) -> LLMRemediationResponse:
    baseline = build_remediation_response(payload)
    model = ollama_model("OLLAMA_REMEDIATION_MODEL")
    prompt = build_prompt(payload, baseline.model_dump())

    try:
        raw_response = call_ollama_generate(model, prompt, num_predict=850)
        parsed = parse_llm_json(raw_response.get("response", ""))
    except OllamaGenerateError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except urllib.error.URLError as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "Ollama is not reachable at 127.0.0.1:11434. Start Ollama and run "
                f"`ollama pull {model}` before generating LLM remediation."
            ),
        ) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Ollama remediation generation failed: {exc}") from exc

    actions = [
        LLMRemediationAction(
            title=item.get("title", "Remediation action"),
            owner=item.get("owner", "Security Team"),
            control=item.get("control", "Security control"),
            effort=item.get("effort", "medium"),
            impact=item.get("impact", "Reduces attack path risk."),
            rationale=item.get("rationale", "Prioritized from attack path context."),
            next_steps=list(item.get("next_steps", []))[:5],
        )
        for item in parsed.get("priority_actions", [])
        if isinstance(item, dict)
    ]

    return LLMRemediationResponse(
        generated=True,
        provider="ollama",
        model=model,
        executive_summary=parsed.get("executive_summary", "Ollama summary was not provided."),
        priority_actions=actions[:5],
        residual_risk=parsed.get("residual_risk", "Residual risk was not provided."),
        assumptions=list(parsed.get("assumptions", []))[:6],
        source_recommendation_count=len(baseline.recommendations),
    )


def build_prompt(payload: RemediationRequest, baseline: dict[str, Any]) -> str:
    compact_network = {
        "nodes": [node.model_dump() for node in payload.network.nodes[:25]],
        "edges": [edge.model_dump() for edge in payload.network.edges[:45]],
    }

    requested_schema = {
        "executive_summary": "short paragraph",
        "priority_actions": [
            {
                "title": "short action title",
                "owner": "team responsible",
                "control": "security control family",
                "effort": "low | medium | high",
                "impact": "one short sentence",
                "rationale": "one short sentence",
                "next_steps": ["step 1", "step 2"],
            }
        ],
        "residual_risk": "one short paragraph",
        "assumptions": ["assumption 1", "assumption 2"],
    }

    context = {
        "selected_entry": payload.entry_point,
        "selected_critical_asset": payload.critical_asset,
        "network": compact_network,
        "baseline_remediation": {
            "baseline_highest_risk": baseline.get("baseline_highest_risk"),
            "recommendations": baseline.get("recommendations", [])[:5],
        },
        "required_output_schema": requested_schema,
    }

    return (
        "You are a senior cybersecurity remediation architect for a desktop breach path simulator.\n"
        "Generate exactly 3 concise remediation actions using only the supplied graph and evidence.\n"
        "Prioritize controls that reduce multiple attack paths or protect critical assets.\n"
        "Keep every field brief so the JSON is compact.\n"
        "Return ONLY valid JSON. Do not include markdown, code fences, or explanation outside JSON.\n\n"
        f"{json.dumps(context, indent=2)}"
    )

