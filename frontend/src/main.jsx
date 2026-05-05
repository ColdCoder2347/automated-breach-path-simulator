import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import axios from "axios";
import cytoscape from "cytoscape";
import "./styles.css";

const API_BASE = window.breachSimulator?.apiBaseUrl ?? "http://127.0.0.1:8765";

function App() {
  const cyRef = useRef(null);
  const graphRef = useRef(null);
  const [network, setNetwork] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [algorithm, setAlgorithm] = useState("dijkstra");
  const [entryPoint, setEntryPoint] = useState("");
  const [criticalAsset, setCriticalAsset] = useState("");
  const [activeStep, setActiveStep] = useState(0);
  const [status, setStatus] = useState("Loading sample topology");

  useEffect(() => {
    axios.get(`${API_BASE}/sample`).then((response) => {
      setNetwork(response.data);
      setStatus("Sample topology loaded");
    }).catch(() => setStatus("Backend is not reachable"));
  }, []);

  useEffect(() => {
    if (!network) return;
    const entries = network.nodes.filter((node) => node.type === "entry");
    const critical = network.nodes.filter((node) => node.type === "critical");
    setEntryPoint((current) => current || entries[0]?.id || network.nodes[0]?.id || "");
    setCriticalAsset((current) => current || critical[0]?.id || network.nodes.at(-1)?.id || "");
  }, [network]);

  const elements = useMemo(() => {
    if (!network) return [];
    return [
      ...network.nodes.map((node) => ({
        data: { id: node.id, label: node.label, type: node.type, assetValue: node.asset_value }
      })),
      ...network.edges.map((edge) => ({
        data: {
          id: `${edge.source}-${edge.target}`,
          source: edge.source,
          target: edge.target,
          label: edge.label,
          cvss: edge.cvss,
          complexity: edge.complexity
        }
      }))
    ];
  }, [network]);

  useEffect(() => {
    if (!cyRef.current || !elements.length) return;
    graphRef.current?.destroy();
    graphRef.current = cytoscape({
      container: cyRef.current,
      elements,
      layout: { name: "breadthfirst", directed: true, padding: 28, spacingFactor: 1.15 },
      style: [
        {
          selector: "node",
          style: {
            "background-color": "#64748b",
            "border-width": 2,
            "border-color": "#cbd5e1",
            "color": "#e2e8f0",
            "font-size": 12,
            "height": 46,
            "label": "data(label)",
            "text-max-width": 118,
            "text-wrap": "wrap",
            "text-valign": "bottom",
            "text-margin-y": 8,
            "width": 46
          }
        },
        { selector: "node[type = 'entry']", style: { "background-color": "#22c55e", "border-color": "#bbf7d0" } },
        { selector: "node[type = 'critical']", style: { "background-color": "#ef4444", "border-color": "#fecaca", "height": 58, "width": 58 } },
        { selector: "node[type = 'database']", style: { "background-color": "#0ea5e9", "border-color": "#bae6fd" } },
        {
          selector: "edge",
          style: {
            "curve-style": "bezier",
            "target-arrow-shape": "triangle",
            "target-arrow-color": "#94a3b8",
            "line-color": "#64748b",
            "width": 2,
            "label": "data(label)",
            "font-size": 10,
            "color": "#cbd5e1",
            "text-background-color": "#111827",
            "text-background-opacity": 0.86,
            "text-background-padding": 3
          }
        },
        { selector: ".path-node", style: { "background-color": "#f59e0b", "border-color": "#fde68a", "border-width": 4 } },
        { selector: ".path-edge", style: { "line-color": "#f59e0b", "target-arrow-color": "#f59e0b", "width": 4 } },
        { selector: ".active-node", style: { "background-color": "#a855f7", "border-color": "#f5d0fe", "height": 66, "width": 66 } }
      ]
    });
  }, [elements]);

  useEffect(() => {
    const graph = graphRef.current;
    if (!graph || !analysis) return;
    graph.elements().removeClass("path-node path-edge active-node");
    analysis.path.forEach((id, index) => {
      graph.getElementById(id).addClass(index === activeStep ? "active-node" : "path-node");
      if (index > 0) {
        graph.getElementById(`${analysis.path[index - 1]}-${id}`).addClass("path-edge");
      }
    });
  }, [analysis, activeStep]);

  async function runSimulation() {
    if (!network) return;
    setStatus("Running breach simulation");
    const response = await axios.post(`${API_BASE}/analyze`, {
      network,
      algorithm,
      entry_point: entryPoint,
      critical_asset: criticalAsset
    });
    setAnalysis(response.data);
    setActiveStep(0);
    setStatus("Simulation complete");
  }

  function playSimulation() {
    if (!analysis?.steps?.length) return;
    let next = 0;
    const timer = setInterval(() => {
      setActiveStep(next);
      next += 1;
      if (next >= analysis.steps.length) clearInterval(timer);
    }, 900);
  }

  async function uploadNetwork(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    const parsed = JSON.parse(await file.text());
    setNetwork(parsed);
    setAnalysis(null);
    setEntryPoint("");
    setCriticalAsset("");
    setStatus(`Loaded ${file.name}`);
  }

  async function exportJson() {
    const response = await axios.post(`${API_BASE}/report/json`, {
      network,
      algorithm,
      entry_point: entryPoint,
      critical_asset: criticalAsset
    });
    downloadBlob(JSON.stringify(response.data, null, 2), "breach-path-report.json", "application/json");
  }

  async function exportPdf() {
    const response = await axios.post(`${API_BASE}/report/pdf`, {
      network,
      algorithm,
      entry_point: entryPoint,
      critical_asset: criticalAsset
    }, { responseType: "blob" });
    downloadBlob(response.data, "breach-path-report.pdf", "application/pdf");
  }

  const entries = network?.nodes.filter((node) => node.type === "entry") ?? [];
  const criticalAssets = network?.nodes.filter((node) => node.type === "critical") ?? [];
  const currentStep = analysis?.steps?.[activeStep];

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div>
          <p className="eyebrow">Desktop Simulator</p>
          <h1>Automated Breach Path Simulator</h1>
        </div>

        <section className="panel">
          <h2>Simulation</h2>
          <label>
            Algorithm
            <select value={algorithm} onChange={(event) => setAlgorithm(event.target.value)}>
              <option value="dijkstra">Dijkstra</option>
              <option value="bfs">BFS</option>
              <option value="dfs">DFS</option>
            </select>
          </label>
          <label>
            Entry point
            <select value={entryPoint} onChange={(event) => setEntryPoint(event.target.value)}>
              {entries.map((node) => <option key={node.id} value={node.id}>{node.label}</option>)}
            </select>
          </label>
          <label>
            Critical asset
            <select value={criticalAsset} onChange={(event) => setCriticalAsset(event.target.value)}>
              {criticalAssets.map((node) => <option key={node.id} value={node.id}>{node.label}</option>)}
            </select>
          </label>
          <button className="primary" onClick={runSimulation}>Run simulation</button>
          <button onClick={playSimulation} disabled={!analysis?.steps?.length}>Play path</button>
        </section>

        <section className="panel">
          <h2>Data</h2>
          <label className="file-picker">
            Upload topology JSON
            <input type="file" accept="application/json" onChange={uploadNetwork} />
          </label>
          <div className="button-row">
            <button onClick={exportJson} disabled={!network}>Export JSON</button>
            <button onClick={exportPdf} disabled={!network}>Export PDF</button>
          </div>
        </section>

        <section className="panel metrics">
          <h2>Risk</h2>
          <strong>{analysis ? analysis.risk_score : "--"}<span>/100</span></strong>
          <p>{status}</p>
        </section>
      </aside>

      <section className="workspace">
        <div className="toolbar">
          <div>
            <h2>Attack Graph</h2>
            <p>{network ? `${network.nodes.length} systems, ${network.edges.length} attack edges` : "No topology loaded"}</p>
          </div>
          <div className="legend">
            <span><i className="entry" /> Entry</span>
            <span><i className="critical" /> Critical</span>
            <span><i className="path" /> Active path</span>
          </div>
        </div>

        <div className="graph-area" ref={cyRef} />

        <div className="bottom-drawer">
          <section>
            <h2>Step-by-step breach</h2>
            {currentStep ? (
              <div className="step-focus">
                <b>{activeStep + 1}. {currentStep.label}</b>
                <span>{currentStep.edge_label ? `Reached via ${currentStep.edge_label} | CVSS ${currentStep.cvss}` : "Initial foothold"}</span>
              </div>
            ) : (
              <p>Run a simulation to inspect attacker movement.</p>
            )}
            <div className="step-list">
              {analysis?.steps.map((step, index) => (
                <button key={step.node_id} className={index === activeStep ? "selected" : ""} onClick={() => setActiveStep(index)}>
                  {index + 1}
                </button>
              ))}
            </div>
          </section>

          <section>
            <h2>Findings</h2>
            <ul>
              {(analysis?.findings ?? ["No analysis has been run yet."]).map((finding) => <li key={finding}>{finding}</li>)}
            </ul>
          </section>
        </div>
      </section>
    </main>
  );
}

function downloadBlob(content, filename, type) {
  const blob = content instanceof Blob ? content : new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

createRoot(document.getElementById("root")).render(<App />);
