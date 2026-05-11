from __future__ import annotations

import json
import os
import re
import socket
import urllib.request
from typing import Any


OLLAMA_GENERATE_URL = os.getenv("OLLAMA_GENERATE_URL", "http://127.0.0.1:11434/api/generate")
OLLAMA_TIMEOUT_SECONDS = int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "300"))
DEFAULT_MODEL = "qwen2.5:7b"


class OllamaGenerateError(RuntimeError):
    pass


def ollama_model(env_name: str) -> str:
    return os.getenv(env_name, os.getenv("OLLAMA_MODEL", DEFAULT_MODEL))


def call_ollama_generate(model: str, prompt: str, num_predict: int = 1400) -> dict[str, Any]:
    request_body = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.2,
            "num_predict": num_predict,
            "num_ctx": 4096,
        },
    }

    request = urllib.request.Request(
        OLLAMA_GENERATE_URL,
        data=json.dumps(request_body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=OLLAMA_TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(detail)
            message = parsed.get("error", detail)
        except json.JSONDecodeError:
            message = detail
        raise OllamaGenerateError(f"Ollama generation failed: {message}") from exc
    except (TimeoutError, socket.timeout) as exc:
        raise OllamaGenerateError(
            f"Ollama generation timed out after {OLLAMA_TIMEOUT_SECONDS} seconds. "
            "The model may still be loading; try again, close memory-heavy apps, or use qwen2.5:3b."
        ) from exc


def parse_llm_json(text: str) -> dict[str, Any]:
    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    cleaned = cleaned.removeprefix("```json").removeprefix("```").removesuffix("```").strip()

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError("Ollama did not return JSON.")
        parsed = json.loads(cleaned[start:end + 1])

    if not isinstance(parsed, dict):
        raise ValueError("Ollama returned JSON, but not an object.")

    return parsed
