from __future__ import annotations

import json
import urllib.error

from fastapi import HTTPException

from backend.attack_engine.graph import build_graph, choose_default, node_ids_by_role, path_steps
from backend.attack_engine.ollama_client import call_ollama_generate, ollama_model, parse_llm_json
from backend.attack_engine.paths import compute_path
from backend.attack_engine.schemas import LLMAttackChainRequest, LLMAttackChainResponse


def build_llm_attack_chain_response(payload: LLMAttackChainRequest) -> LLMAttackChainResponse:
    graph = build_graph(payload.network)
    entry_points = node_ids_by_role(payload.network, "entry")
    critical_assets = node_ids_by_role(payload.network, "critical")
    selected_entry = payload.entry_point or choose_default(entry_points, payload.network.nodes)
    selected_critical = payload.critical_asset or choose_default(critical_assets, payload.network.nodes[::-1])
    path = compute_path(graph, selected_entry, selected_critical, payload.algorithm) if selected_entry and selected_critical else []
    steps = [step.model_dump() for step in path_steps(graph, path)]
    model = ollama_model("OLLAMA_ATTACK_CHAIN_MODEL")
    prompt = build_prompt(payload, path, steps)

    try:
        raw_response = call_ollama_generate(model, prompt, num_predict=1200)
        parsed = parse_llm_json(raw_response.get("response", ""))
    except urllib.error.URLError as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "Ollama is not reachable at 127.0.0.1:11434. Start Ollama and run "
                f"`ollama pull {model}` before generating the attack chain narrative."
            ),
        ) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Ollama attack chain generation failed: {exc}") from exc

    return LLMAttackChainResponse(
        generated=True,
        provider="ollama",
        model=model,
        title=parsed.get("title", "Attack Chain Narrative"),
        narrative=parsed.get("narrative", "No narrative was generated."),
        kill_chain=list(parsed.get("kill_chain", []))[:8],
        attacker_objective=parsed.get("attacker_objective", "Compromise the selected critical asset."),
        detection_opportunities=list(parsed.get("detection_opportunities", []))[:6],
        path=path,
    )


def build_prompt(payload: LLMAttackChainRequest, path: list[str], steps: list[dict]) -> str:
    context = {
        "algorithm": payload.algorithm.value,
        "selected_entry": payload.entry_point,
        "selected_critical_asset": payload.critical_asset,
        "path": path,
        "steps": steps,
        "edges": [edge.model_dump() for edge in payload.network.edges[:80]],
        "required_output_schema": {
            "title": "short title",
            "narrative": "one concise paragraph explaining attacker movement",
            "kill_chain": ["stage 1", "stage 2", "stage 3"],
            "attacker_objective": "objective",
            "detection_opportunities": ["detection 1", "detection 2"],
        },
    }

    return (
        "You are explaining a simulated cybersecurity breach path in a desktop attack graph tool.\n"
        "Describe how an attacker moves from the selected entry point to the critical asset.\n"
        "Use only the supplied path, steps, edge labels, CVSS values, and MITRE fields.\n"
        "Be realistic and concise. Do not invent systems that are not in the input.\n"
        "Return ONLY valid JSON. Do not include markdown or prose outside JSON.\n\n"
        f"{json.dumps(context, indent=2)}"
    )
