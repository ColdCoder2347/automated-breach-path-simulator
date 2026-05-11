# Automated Breach Path Simulator

An Electron desktop application that models network infrastructure as an attack graph and simulates likely breach paths using a Python backend powered by NetworkX.

## Features

- BFS, DFS, and Dijkstra attack path simulation
- Entry point and critical asset detection
- Risk scoring using CVSS, asset value, and path complexity
- Interactive Cytoscape.js graph visualization
- Step-by-step breach path playback
- PDF and JSON topology upload
- JSON and PDF report export

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
npm.cmd install
```

PowerShell may block `npm`; use `npm.cmd` as shown.

## Run

```powershell
npm.cmd run dev
```

This starts:

- FastAPI backend at `http://127.0.0.1:8765`
- Vite renderer at `http://127.0.0.1:5173`
- Electron desktop shell

## Local LLM Remediation

The remediation dashboard can generate an AI action plan through local Ollama, so no cloud API key is required.

```powershell
ollama pull qwen2.5:7b
ollama serve
npm.cmd run dev
```

Optional model override:

```powershell
$env:OLLAMA_MODEL="qwen2.5:7b"
$env:OLLAMA_REMEDIATION_MODEL="qwen2.5:7b"
$env:OLLAMA_ATTACK_CHAIN_MODEL="qwen2.5:7b"
$env:OLLAMA_MITIGATION_MODEL="qwen2.5:7b"
```

## Network Data Format

Upload a JSON file with this shape. If `asset_value`, `cvss`, or `complexity` are missing, the backend estimates them from the uploaded labels and metadata instead of loading demo values.

```json
{
  "nodes": [
    { "id": "vpn", "label": "VPN Gateway", "type": "entry", "asset_value": 4 },
    { "id": "db", "label": "Customer Database", "type": "critical", "asset_value": 10 }
  ],
  "edges": [
    { "source": "vpn", "target": "db", "label": "Weak service account", "cvss": 8.8, "complexity": 3 }
  ]
}
```

Node `type` can be `entry`, `user`, `server`, `database`, or `critical`.

## Backend API

- `GET /health`
- `POST /topology/upload`
- `POST /validate-topology`
- `POST /analyze`
- `POST /paths/top`
- `POST /remediation/recommend`
- `POST /remediation/llm`
- `POST /attack-chain/llm`
- `POST /mitigation/simulate`
- `POST /report/json`
- `POST /report/pdf`
