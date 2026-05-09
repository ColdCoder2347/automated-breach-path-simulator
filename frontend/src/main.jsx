import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

import {
  analyzeNetwork,
  exportJsonReport,
  exportPdfReport,
  getSampleNetwork,
  getTopPaths,
  recommendRemediation,
  validateTopology
} from "./services/breachApi";
import { AttackGraph } from "./features/graph/AttackGraph";
import { MitreChainPanel } from "./features/mitre/MitreChainPanel";
import { TopPathsPanel } from "./features/paths/TopPathsPanel";
import { RemediationPanel } from "./features/remediation/RemediationPanel";
import { ReportActions } from "./features/reports/ReportActions";
import { SimulationControls } from "./features/simulation/SimulationControls";
import { StepTimeline } from "./features/simulation/StepTimeline";
import { TopologyValidationPanel } from "./features/topology/TopologyValidationPanel";

function App() {
  const [network, setNetwork] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [topPaths, setTopPaths] = useState(null);
  const [selectedTopPath, setSelectedTopPath] = useState(null);
  const [remediation, setRemediation] = useState(null);
  const [validation, setValidation] = useState(null);
  const [algorithm, setAlgorithm] = useState("dijkstra");
  const [entryPoint, setEntryPoint] = useState("");
  const [criticalAsset, setCriticalAsset] = useState("");
  const [activeStep, setActiveStep] = useState(0);
  const [status, setStatus] = useState("Loading sample topology");

  useEffect(() => {
    async function loadSample() {
      try {
        const sample = await getSampleNetwork();
        setNetwork(sample);
        setValidation(await validateTopology(sample));
        setStatus("Sample topology loaded");
      } catch {
        setStatus("Local backend is not reachable");
      }
    }

    loadSample();
  }, []);

  useEffect(() => {
    if (!network) return;
    const entries = network.nodes.filter((node) => node.type === "entry");
    const critical = network.nodes.filter((node) => node.type === "critical");
    setEntryPoint((current) => current || entries[0]?.id || network.nodes[0]?.id || "");
    setCriticalAsset((current) => current || critical[0]?.id || network.nodes.at(-1)?.id || "");
  }, [network]);

  const entries = network?.nodes.filter((node) => node.type === "entry") ?? [];
  const criticalAssets = network?.nodes.filter((node) => node.type === "critical") ?? [];
  const activePath = selectedTopPath?.path ?? analysis?.path ?? [];
  const activeSteps = selectedTopPath?.steps ?? analysis?.steps ?? [];
  const currentStep = activeSteps[activeStep];
  const activeMitreChain = selectedTopPath?.mitre_chain ?? currentStepMitreChain(activeSteps);
  const requestPayload = useMemo(() => ({
    network,
    algorithm,
    entry_point: entryPoint,
    critical_asset: criticalAsset
  }), [network, algorithm, entryPoint, criticalAsset]);

  async function runSimulation() {
    if (!network) return;
    setStatus("Running local breach analysis");
    const pathPayload = { network, entry_point: entryPoint, critical_asset: criticalAsset, limit: 5 };
    const [analysisResult, topPathResult, remediationResult, validationResult] = await Promise.all([
      analyzeNetwork(requestPayload),
      getTopPaths(pathPayload),
      recommendRemediation(pathPayload),
      validateTopology(network)
    ]);

    setAnalysis(analysisResult);
    setTopPaths(topPathResult);
    setSelectedTopPath(topPathResult.paths[0] ?? null);
    setRemediation(remediationResult);
    setValidation(validationResult);
    setActiveStep(0);
    setStatus("Local analysis complete");
  }

  function playSimulation() {
    if (!activeSteps.length) return;
    let next = 0;
    const timer = setInterval(() => {
      setActiveStep(next);
      next += 1;
      if (next >= activeSteps.length) clearInterval(timer);
    }, 900);
  }

  async function uploadNetwork(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    const parsed = JSON.parse(await file.text());
    setNetwork(parsed);
    setValidation(await validateTopology(parsed));
    setAnalysis(null);
    setTopPaths(null);
    setSelectedTopPath(null);
    setRemediation(null);
    setEntryPoint("");
    setCriticalAsset("");
    setActiveStep(0);
    setStatus(`Loaded ${file.name}`);
  }

  async function exportJson() {
    const response = await exportJsonReport(requestPayload);
    downloadBlob(JSON.stringify(response, null, 2), "breach-path-report.json", "application/json");
  }

  async function exportPdf() {
    const response = await exportPdfReport(requestPayload);
    downloadBlob(response, "breach-path-report.pdf", "application/pdf");
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div>
          <p className="eyebrow">Desktop Simulator</p>
          <h1>Automated Breach Path Simulator</h1>
        </div>

        <SimulationControls
          algorithm={algorithm}
          criticalAsset={criticalAsset}
          criticalAssets={criticalAssets}
          entries={entries}
          entryPoint={entryPoint}
          hasPath={activeSteps.length > 0}
          onAlgorithmChange={setAlgorithm}
          onCriticalAssetChange={setCriticalAsset}
          onEntryPointChange={setEntryPoint}
          onPlay={playSimulation}
          onRun={runSimulation}
        />

        <ReportActions
          disabled={!network}
          onExportJson={exportJson}
          onExportPdf={exportPdf}
          onUpload={uploadNetwork}
        />

        <section className="panel metrics">
          <h2>Risk</h2>
          <strong>{analysis ? analysis.risk_score : "--"}<span>/100</span></strong>
          <p>{status}</p>
        </section>

        <TopologyValidationPanel validation={validation} compact />
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

        <AttackGraph activePath={activePath} activeStep={activeStep} network={network} />

        <div className="intelligence-grid">
          <StepTimeline
            activeStep={activeStep}
            currentStep={currentStep}
            steps={activeSteps}
            onStepSelect={setActiveStep}
          />
          <TopPathsPanel
            selectedPath={selectedTopPath}
            topPaths={topPaths}
            onSelectPath={(path) => {
              setSelectedTopPath(path);
              setActiveStep(0);
            }}
          />
          <MitreChainPanel chain={activeMitreChain} currentStep={currentStep} />
          <RemediationPanel remediation={remediation} />
        </div>
      </section>
    </main>
  );
}

function currentStepMitreChain(steps) {
  return steps
    .filter((step) => step.mitre_tactic)
    .map((step) => `${step.mitre_tactic}: ${step.mitre_technique}${step.mitre_id ? ` (${step.mitre_id})` : ""}`);
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
