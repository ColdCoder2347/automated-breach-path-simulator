# Automated Breach Path Simulator

An Electron desktop application that models network infrastructure as an attack graph and simulates likely breach paths using a Python backend powered by NetworkX.

## Features

- BFS, DFS, and Dijkstra attack path simulation
- Entry point and critical asset detection
- Risk scoring using CVSS, asset value, and path complexity
- Interactive Cytoscape.js graph visualization
- Step-by-step breach path playback
- JSON topology upload
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
ollama pull qwen3:6b
ollama serve
npm.cmd run dev
```

Optional model override:

```powershell
$env:OLLAMA_REMEDIATION_MODEL="qwen3:6b"
$env:OLLAMA_ATTACK_CHAIN_MODEL="qwen3:6b"
```

## Network Data Format

Upload a JSON file with this shape:

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

## Detailed Sample Scenario

A larger test topology is included at:

```text
samples/enterprise-breach-scenario.json
```

Use the app's upload control to load it. Good test combinations:

- Entry: `Internet Phishing Campaign`; Critical asset: `Customer Database`
- Entry: `VPN Gateway`; Critical asset: `Secrets Vault`
- Entry: `Supplier Portal`; Critical asset: `Payment Database`

Try switching between Dijkstra, BFS, and DFS to compare the easiest weighted attack path against simple graph traversal behavior.

## Backend API

- `GET /health`
- `GET /sample`
- `POST /analyze`
- `POST /report/json`
- `POST /report/pdf`
