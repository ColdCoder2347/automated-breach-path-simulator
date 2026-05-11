import React, {
  useEffect,
  useMemo,
  useRef,
  useState
} from "react";

import { createRoot } from "react-dom/client";

import axios from "axios";

import cytoscape from "cytoscape";

import "./styles.css";

const API_BASE =
  window.breachSimulator?.apiBaseUrl ??
  "http://127.0.0.1:8765";

function App() {

  const cyRef = useRef(null);

  const graphRef = useRef(null);

  const fileInputRef = useRef(null);

  const [network, setNetwork] = useState(null);

  const [analysis, setAnalysis] = useState(null);

  const [llmRemediation, setLlmRemediation] =
    useState(null);

  const [llmLoading, setLlmLoading] =
    useState(false);

  const [llmError, setLlmError] =
    useState("");

  const [chainNarrative, setChainNarrative] =
    useState(null);

  const [chainLoading, setChainLoading] =
    useState(false);

  const [chainError, setChainError] =
    useState("");

  const [mitigationResult, setMitigationResult] =
    useState(null);

  const [mitigationLoading, setMitigationLoading] =
    useState(false);

  const [mitigationError, setMitigationError] =
    useState("");

  const [mitigationEdge, setMitigationEdge] =
    useState("");

  const [mitigationMode, setMitigationMode] =
    useState("block_edge");

  const [algorithm, setAlgorithm] =
    useState("dijkstra");

  const [entryPoint, setEntryPoint] =
    useState("");

  const [criticalAsset, setCriticalAsset] =
    useState("");

  const [activeStep, setActiveStep] =
    useState(0);

  const [status, setStatus] =
    useState("Waiting for upload");

  // =====================================================
  // AUTO ENTRY / CRITICAL
  // =====================================================

  useEffect(() => {

    if (
      !network ||
      !Array.isArray(network.nodes)
    ) {
      return;
    }

    const entries =
      network.nodes.filter(
        (n) => n.type === "entry"
      );

    const critical =
      network.nodes.filter(
        (n) => n.type === "critical"
      );

    setEntryPoint(
      entries[0]?.id ??
      network.nodes[0]?.id ??
      ""
    );

    setCriticalAsset(
      critical[0]?.id ??
      network.nodes.at(-1)?.id ??
      ""
    );

    const firstEdge =
      network.edges?.[0];

    setMitigationEdge(
      firstEdge
        ? `${firstEdge.source}->${firstEdge.target}`
        : ""
    );

  }, [network]);

  // =====================================================
  // CYTOSCAPE ELEMENTS
  // =====================================================

  const elements = useMemo(() => {

    if (
      !network ||
      !Array.isArray(network.nodes)
    ) {
      return [];
    }

    const nodes =
      network.nodes.map((node) => ({

        data: {
          id: node.id,
          label:
            node.label ??
            node.id,
          type:
            node.type ??
            "server",
          assetValue:
            node.asset_value ?? 5
        }

      }));

    const nodeIds =
      new Set(
        nodes.map((n) => n.data.id)
      );

    const edges =
      (network.edges ?? [])

      .filter(
        (edge) =>
          nodeIds.has(edge.source) &&
          nodeIds.has(edge.target)
      )

      .map((edge, index) => ({

        data: {
          id:
            `${edge.source}-${edge.target}-${index}`,
          source: edge.source,
          target: edge.target,
          label:
            edge.label ??
            "connection",
          cvss:
            edge.cvss ?? 5,
          complexity:
            edge.complexity ?? 3
        }

      }));

    return [...nodes, ...edges];

  }, [network]);

  // =====================================================
  // CYTOSCAPE GRAPH
  // =====================================================

  useEffect(() => {

    if (!cyRef.current) {
      return;
    }

    graphRef.current?.destroy();

    if (!elements.length) {
      return;
    }

    graphRef.current = cytoscape({

      container: cyRef.current,

      elements,

      layout: buildGraphLayout(network),

      style: [

        {
          selector: "node",

          style: {

            "background-color":
              "#64748b",

            "border-width": 2,

            "border-color":
              "#cbd5e1",

            "label":
              "data(label)",

            "font-size": 12,

            "text-wrap": "wrap",

            "text-max-width": 120,

            "color": "#ffffff",

            "text-valign": "bottom",

            "text-margin-y": 8,

            "height": 48,

            "width": 48
          }
        },

        {
          selector:
            "node[type = 'entry']",

          style: {
            "background-color":
              "#22c55e"
          }
        },

        {
          selector:
            "node[type = 'database']",

          style: {
            "background-color":
              "#0ea5e9"
          }
        },

        {
          selector:
            "node[type = 'critical']",

          style: {
            "background-color":
              "#ef4444",

            "height": 60,

            "width": 60
          }
        },

        {
          selector: "edge",

          style: {

            "curve-style":
              "bezier",

            "target-arrow-shape":
              "triangle",

            "line-color":
              "#64748b",

            "target-arrow-color":
              "#64748b",

            "width": 2,

            "label":
              "data(label)",

            "font-size": 10,

            "color": "#cbd5e1",

            "text-background-opacity":
              1,

            "text-background-color":
              "#111827",

            "text-background-padding":
              3
          }
        },

        {
          selector:
            ".path-node",

          style: {
            "background-color":
              "#f59e0b"
          }
        },

        {
          selector:
            ".path-edge",

          style: {
            "line-color":
              "#f59e0b",

            "target-arrow-color":
              "#f59e0b",

            "width": 4
          }
        }

      ]

    });

    requestAnimationFrame(() => {
      graphRef.current?.resize();
      graphRef.current?.fit(undefined, 40);
    });

    return () => {
      graphRef.current?.destroy();
    };

  }, [elements]);

  // =====================================================
  // PATH HIGHLIGHTING
  // =====================================================

  useEffect(() => {

    const graph =
      graphRef.current;

    if (
      !graph ||
      !analysis?.path
    ) {
      return;
    }

    graph
      .elements()
      .removeClass(
        "path-node path-edge"
      );

    analysis.path.forEach(
      (id, index) => {

        const node =
          graph.getElementById(id);

        node.addClass("path-node");

        if (index > 0) {

          const edge =
            graph.edges().filter(
              (e) =>
                e.data("source") ===
                  analysis.path[index - 1] &&
                e.data("target") === id
            );

          edge.addClass("path-edge");
        }
      }
    );

  }, [analysis]);

  // =====================================================
  // RUN SIMULATION
  // =====================================================

  async function runSimulation() {

    if (!network) {
      return;
    }

    try {

      setStatus(
        "Running simulation..."
      );

      const response =
        await axios.post(
          `${API_BASE}/analyze`,
          {

            network,

            algorithm,

            entry_point:
              entryPoint,

            critical_asset:
              criticalAsset
          }
        );

      setAnalysis(response.data);

      setLlmRemediation(null);

      setLlmError("");

      setChainNarrative(null);

      setChainError("");

      setMitigationResult(null);

      setMitigationError("");

      setStatus(
        "Simulation complete"
      );

    } catch (error) {

      setStatus(
        "Simulation failed"
      );

    }
  }

  // =====================================================
  // FILE UPLOAD
  // =====================================================

  async function uploadNetwork(event) {

    const file =
      event.target.files?.[0];

    if (!file) {
      return;
    }

    const ext =
      file.name
        .split(".")
        .pop()
        ?.toLowerCase();

    if (
      ext !== "pdf" &&
      ext !== "json"
    ) {

      setStatus(
        "Only PDF and JSON supported"
      );

      return;
    }

    try {

      setStatus(
        `Parsing ${file.name}...`
      );

      const formData =
        new FormData();

      formData.append(
        "file",
        file
      );

      const response =
        await axios.post(
          `${API_BASE}/topology/upload`,
          formData,
          {
            headers: {
              "Content-Type":
                "multipart/form-data"
            }
          }
        );

      const parsed =
        response.data.network;

      if (
        !parsed ||
        !Array.isArray(parsed.nodes) ||
        !Array.isArray(parsed.edges)
      ) {
        throw new Error(
          "Parser did not return a valid graph."
        );
      }

      if (!parsed.nodes.length) {
        throw new Error(
          "No nodes could be extracted from this file."
        );
      }

      setNetwork(parsed);

      setAnalysis(null);

      setLlmRemediation(null);

      setLlmError("");

      setChainNarrative(null);

      setChainError("");

      setMitigationResult(null);

      setMitigationError("");

      setStatus(
        `Loaded ${parsed.nodes.length} nodes and ${parsed.edges.length} edges from ${file.name}`
      );

    } catch (error) {

      console.error(error);

      const detail =
        error.response?.data?.detail ??
        error.message ??
        "Upload failed";

      setStatus(
        `Upload failed: ${detail}`
      );

    } finally {
      event.target.value = "";
    }
  }

  // =====================================================
  // LLM REMEDIATION
  // =====================================================

  async function generateLlmRemediation() {

    if (!network) {
      return;
    }

    try {

      setLlmLoading(true);

      setLlmError("");

      setLlmRemediation(null);

      const response =
        await axios.post(
          `${API_BASE}/remediation/llm`,
          {
            network,
            entry_point:
              entryPoint,
            critical_asset:
              criticalAsset,
            limit: 5
          }
        );

      setLlmRemediation(
        response.data
      );

    } catch (error) {

      const detail =
        error.response?.data?.detail ??
        error.message ??
        "LLM remediation failed";

      setLlmError(detail);

    } finally {

      setLlmLoading(false);

    }
  }

  async function generateAttackChainNarrative() {

    if (!network) {
      return;
    }

    try {

      setChainLoading(true);

      setChainError("");

      setChainNarrative(null);

      const response =
        await axios.post(
          `${API_BASE}/attack-chain/llm`,
          {
            network,
            algorithm,
            entry_point:
              entryPoint,
            critical_asset:
              criticalAsset
          }
        );

      setChainNarrative(
        response.data
      );

    } catch (error) {

      const detail =
        error.response?.data?.detail ??
        error.message ??
        "Attack chain generation failed";

      setChainError(detail);

    } finally {

      setChainLoading(false);

    }
  }

  async function runMitigationSimulation() {

    if (!network || !mitigationEdge) {
      return;
    }

    try {

      setMitigationLoading(true);

      setMitigationError("");

      setMitigationResult(null);

      const response =
        await axios.post(
          `${API_BASE}/mitigation/simulate`,
          {
            network,
            entry_point:
              entryPoint,
            critical_asset:
              criticalAsset,
            limit: 5,
            target_edge:
              mitigationEdge,
            mode:
              mitigationMode
          }
        );

      setMitigationResult(
        response.data
      );

    } catch (error) {

      const detail =
        error.response?.data?.detail ??
        error.message ??
        "Mitigation simulation failed";

      setMitigationError(detail);

    } finally {

      setMitigationLoading(false);

    }
  }

  // =====================================================
  // EXPORTS
  // =====================================================

  async function exportJson() {

    if (!network) {
      return;
    }

    const response =
      await axios.post(
        `${API_BASE}/report/json`,
        {

          network,

          algorithm,

          entry_point:
            entryPoint,

          critical_asset:
            criticalAsset
        }
      );

    downloadBlob(
      JSON.stringify(
        response.data,
        null,
        2
      ),
      "breach-report.json",
      "application/json"
    );
  }

  async function exportPdf() {

    if (!network) {
      return;
    }

    const response =
      await axios.post(
        `${API_BASE}/report/pdf`,
        {

          network,

          algorithm,

          entry_point:
            entryPoint,

          critical_asset:
            criticalAsset
        },
        {
          responseType: "blob"
        }
      );

    downloadBlob(
      response.data,
      "breach-report.pdf",
      "application/pdf"
    );
  }

  // =====================================================
  // UI
  // =====================================================

  const entries =
    network?.nodes?.filter(
      (n) => n.type === "entry"
    ) ?? [];

  const criticalAssets =
    network?.nodes?.filter(
      (n) => n.type === "critical"
    ) ?? [];

  const mitigationOptions =
    network?.edges?.map((edge) => {
      const sourceLabel =
        network.nodes.find(
          (node) => node.id === edge.source
        )?.label ?? edge.source;

      const targetLabel =
        network.nodes.find(
          (node) => node.id === edge.target
        )?.label ?? edge.target;

      return {
        id: `${edge.source}->${edge.target}`,
        label: `${sourceLabel} -> ${targetLabel} (${edge.label ?? "connection"})`
      };
    }) ?? [];

  const selectedAlgorithmLabel =
    {
      bfs: "BFS",
      dfs: "DFS",
      dijkstra: "Dijkstra"
    }[analysis?.algorithm ?? algorithm] ?? algorithm;

  const attackPathLabels =
    analysis?.steps?.map((step) => step.label) ?? [];

  return (

    <main className="app-shell">

      <aside className="sidebar">

        <h1>
          Automated Breach
          Path Simulator
        </h1>

        <section className="panel">

          <h2>Upload</h2>

          <button
            className="primary"
            onClick={() =>
              fileInputRef.current?.click()
            }
          >
            Upload PDF / JSON
          </button>

          <input
            ref={fileInputRef}
            type="file"
            accept=".pdf,.json"
            hidden
            onChange={uploadNetwork}
          />

          <p>{status}</p>

        </section>

        <section className="panel">

          <h2>Simulation</h2>

          <label>
            Path algorithm
            <select
              value={algorithm}
              onChange={(event) => {
                setAlgorithm(event.target.value);
                setAnalysis(null);
                setChainNarrative(null);
                setMitigationResult(null);
                setStatus("Algorithm changed. Run simulation again.");
              }}
            >
              <option value="dijkstra">
                Dijkstra - weighted lowest-cost path
              </option>
              <option value="bfs">
                BFS - shortest hop path
              </option>
              <option value="dfs">
                DFS - depth-first traversal path
              </option>
            </select>
          </label>

          <label>
            Entry point
            <select
              value={entryPoint}
              onChange={(event) => {
                setEntryPoint(event.target.value);
                setAnalysis(null);
              }}
            >
              {entries.map((entry) => (
                <option
                  key={entry.id}
                  value={entry.id}
                >
                  {entry.label}
                </option>
              ))}
            </select>
          </label>

          <label>
            Critical asset
            <select
              value={criticalAsset}
              onChange={(event) => {
                setCriticalAsset(event.target.value);
                setAnalysis(null);
              }}
            >
              {criticalAssets.map((asset) => (
                <option
                  key={asset.id}
                  value={asset.id}
                >
                  {asset.label}
                </option>
              ))}
            </select>
          </label>

          <button
            onClick={runSimulation}
            disabled={!network}
          >
            Run Simulation
          </button>

          <button
            className="primary"
            onClick={generateLlmRemediation}
            disabled={!network || llmLoading}
          >
            {llmLoading
              ? "Generating..."
              : "Generate LLM Remediation"}
          </button>

          <button
            onClick={generateAttackChainNarrative}
            disabled={!network || chainLoading}
          >
            {chainLoading
              ? "Describing..."
              : "Describe Attack Chain"}
          </button>

          <button
            onClick={runMitigationSimulation}
            disabled={!network || !mitigationEdge || mitigationLoading}
          >
            {mitigationLoading
              ? "Simulating..."
              : "Simulate Mitigation"}
          </button>

          <button
            onClick={exportJson}
            disabled={!network}
          >
            Export JSON
          </button>

          <button
            onClick={exportPdf}
            disabled={!network}
          >
            Export PDF
          </button>

        </section>

      </aside>

      <section className="workspace">

        <div className="graph-shell">
          <div
            className="graph-area"
            ref={cyRef}
          />

          {!network && (
            <div className="upload-empty-state">
              <p className="eyebrow">
                Upload Required
              </p>
              <h2>
                Import a PDF or JSON topology to generate the attack graph
              </h2>
              <p>
                Nodes, edges, severity, complexity, entry points, and critical assets are derived from the uploaded file.
              </p>
              <button
                className="primary"
                onClick={() =>
                  fileInputRef.current?.click()
                }
              >
                Upload Topology
              </button>
            </div>
          )}
        </div>

        <section className="llm-dashboard">

          <section className="path-panel">
            <div className="dashboard-header compact">
              <div>
                <p className="eyebrow">
                  Attack Path
                </p>
                <h2>
                  {selectedAlgorithmLabel} simulation result
                </h2>
              </div>
              <span className="risk-pill">
                Risk {analysis ? `${analysis.risk_score}/100` : "--"}
              </span>
            </div>

            {!analysis && (
              <div className="llm-empty">
                <b>
                  No algorithm result yet
                </b>
                <p>
                  Choose BFS, DFS, or Dijkstra, then run the simulation to highlight and list the selected attack path.
                </p>
              </div>
            )}

            {analysis && !analysis.path.length && (
              <div className="llm-error">
                <b>
                  No reachable path
                </b>
                <p>
                  {selectedAlgorithmLabel} could not find a route from the selected entry point to the critical asset.
                </p>
              </div>
            )}

            {analysis && analysis.path.length > 0 && (
              <div className="path-result">
                <div className="path-route">
                  {attackPathLabels.map((label, index) => (
                    <span key={`${label}-${index}`}>
                      {label}
                    </span>
                  ))}
                </div>

                <ol className="path-steps">
                  {analysis.steps.map((step) => (
                    <li key={`${step.node_id}-${step.index}`}>
                      <b>
                        {step.index + 1}. {step.label}
                      </b>
                      <small>
                        {step.edge_label
                          ? `via ${step.edge_label} | CVSS ${step.cvss} | Complexity ${step.complexity}`
                          : step.type}
                      </small>
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </section>

          <div className="dashboard-header">

            <div>
              <p className="eyebrow">
                AI Remediation
              </p>
              <h2>
                LLM-generated action plan
              </h2>
            </div>

            <button
              onClick={generateLlmRemediation}
              disabled={!network || llmLoading}
            >
              {llmLoading
                ? "Generating"
                : "Refresh"}
            </button>

          </div>

          <section className="chain-panel">

            <div className="dashboard-header compact">
              <div>
                <p className="eyebrow">
                  Simulation Chain
                </p>
                <h2>
                  Attacker movement narrative
                </h2>
              </div>
              <button
                onClick={generateAttackChainNarrative}
                disabled={!network || chainLoading}
              >
                {chainLoading
                  ? "Describing"
                  : "Generate"}
              </button>
            </div>

            {chainLoading && (
              <div className="llm-loading slim">
                <div className="loader-ring" />
                <p>
                  Qwen is describing how the attacker moves through the selected graph path.
                </p>
              </div>
            )}

            {!chainLoading && chainError && (
              <div className="llm-error">
                <b>
                  Attack chain narrative unavailable
                </b>
                <p>{chainError}</p>
              </div>
            )}

            {!chainLoading && !chainError && !chainNarrative && (
              <div className="llm-empty">
                <b>
                  No chain narrative yet
                </b>
                <p>
                  Generate a simulation chain description to explain the attacker's movement through the graph.
                </p>
              </div>
            )}

            {!chainLoading && chainNarrative && (
              <div className="chain-content">
                <article className="summary-card">
                  <span>
                    {chainNarrative.title}
                  </span>
                  <p>
                    {chainNarrative.narrative}
                  </p>
                  <small>
                    Objective: {chainNarrative.attacker_objective}
                  </small>
                </article>

                <div className="chain-columns">
                  <div>
                    <h3>
                      Kill Chain
                    </h3>
                    <ol>
                      {chainNarrative.kill_chain.map(
                        (step) => (
                          <li key={step}>
                            {step}
                          </li>
                        )
                      )}
                    </ol>
                  </div>
                  <div>
                    <h3>
                      Detection Opportunities
                    </h3>
                    <ul>
                      {chainNarrative.detection_opportunities.map(
                        (item) => (
                          <li key={item}>
                            {item}
                          </li>
                        )
                      )}
                    </ul>
                  </div>
                </div>
              </div>
            )}

          </section>

          <section className="mitigation-panel">

            <div className="dashboard-header compact">
              <div>
                <p className="eyebrow">
                  Before / After
                </p>
                <h2>
                  Mitigation simulation
                </h2>
              </div>
              <button
                onClick={runMitigationSimulation}
                disabled={!network || !mitigationEdge || mitigationLoading}
              >
                {mitigationLoading
                  ? "Simulating"
                  : "Run"}
              </button>
            </div>

            <div className="mitigation-controls">
              <label>
                Attack edge
                <select
                  value={mitigationEdge}
                  onChange={(event) =>
                    setMitigationEdge(event.target.value)
                  }
                >
                  {mitigationOptions.map(
                    (option) => (
                      <option
                        key={option.id}
                        value={option.id}
                      >
                        {option.label}
                      </option>
                    )
                  )}
                </select>
              </label>
              <label>
                Mitigation mode
                <select
                  value={mitigationMode}
                  onChange={(event) =>
                    setMitigationMode(event.target.value)
                  }
                >
                  <option value="block_edge">
                    Block edge
                  </option>
                  <option value="weaken_edge">
                    Weaken edge
                  </option>
                </select>
              </label>
            </div>

            {mitigationLoading && (
              <div className="llm-loading slim">
                <div className="loader-ring" />
                <p>
                  Estimating post-mitigation values with Qwen/Ollama, then recomputing ranked paths.
                </p>
              </div>
            )}

            {!mitigationLoading && mitigationError && (
              <div className="llm-error">
                <b>
                  Mitigation simulation failed
                </b>
                <p>{mitigationError}</p>
              </div>
            )}

            {!mitigationLoading && !mitigationError && !mitigationResult && (
              <div className="llm-empty">
                <b>
                  No mitigation simulated yet
                </b>
                <p>
                  Select an edge and run a virtual mitigation to compare risk before and after.
                </p>
              </div>
            )}

            {!mitigationLoading && mitigationResult && (
              <div className="mitigation-results">
                <div className="risk-compare">
                  <article>
                    <span>
                      Before
                    </span>
                    <b>
                      {mitigationResult.baseline_highest_risk}
                    </b>
                  </article>
                  <article>
                    <span>
                      After
                    </span>
                    <b>
                      {mitigationResult.mitigated_highest_risk}
                    </b>
                  </article>
                  <article className="reduction">
                    <span>
                      Reduction
                    </span>
                    <b>
                      {mitigationResult.risk_reduction}
                    </b>
                  </article>
                </div>

                <p>
                  {mitigationResult.summary}
                </p>

                <div className="mitigation-stats">
                  <span>
                    Blocked paths: {mitigationResult.blocked_path_count}
                  </span>
                  <span>
                    Baseline paths: {mitigationResult.baseline_path_count}
                  </span>
                  <span>
                    Remaining paths: {mitigationResult.mitigated_path_count}
                  </span>
                </div>

                {mitigationResult.estimate && (
                  <div className="ai-estimate">
                    <div>
                      <span>
                        Estimate source
                      </span>
                      <b>
                        {mitigationResult.estimate.generated_by_llm
                          ? `${mitigationResult.estimate.model ?? "Qwen"} via Ollama`
                          : "Metadata risk model"}
                      </b>
                    </div>
                    <div>
                      <span>
                        Confidence
                      </span>
                      <b>
                        {Math.round((mitigationResult.estimate.confidence ?? 0) * 100)}%
                      </b>
                    </div>
                    <div>
                      <span>
                        Post-mitigation CVSS
                      </span>
                      <b>
                        {mitigationResult.estimate.cvss_after}
                      </b>
                    </div>
                    <div>
                      <span>
                        Post-mitigation complexity
                      </span>
                      <b>
                        {mitigationResult.estimate.complexity_after}
                      </b>
                    </div>
                    <p>
                      {mitigationResult.estimate.rationale}
                    </p>
                  </div>
                )}
              </div>
            )}

          </section>

          {llmLoading && (
            <div className="llm-loading">
              <div className="loader-ring" />
              <div>
                <b>
                  Generating remediation plan
                </b>
                <p>
                  The local backend is sending the current graph, critical path context, and ranked remediation evidence to the LLM.
                </p>
              </div>
            </div>
          )}

          {!llmLoading && llmError && (
            <div className="llm-error">
              <b>
                LLM generation unavailable
              </b>
              <p>{llmError}</p>
              <small>
                Start Ollama locally and run `ollama pull qwen2.5:7b`, then try again.
              </small>
            </div>
          )}

          {!llmLoading && !llmError && !llmRemediation && (
            <div className="llm-empty">
              <b>
                No AI plan generated yet
              </b>
              <p>
                Upload or load a topology, then generate an LLM remediation plan for the current entry point and critical asset.
              </p>
            </div>
          )}

          {!llmLoading && llmRemediation && (
            <div className="llm-content">

              <article className="summary-card">
                <span>
                  Executive Summary
                </span>
                <p>
                  {llmRemediation.executive_summary}
                </p>
                <small>
                  Provider: {llmRemediation.provider}
                  {llmRemediation.model
                    ? ` | Model: ${llmRemediation.model}`
                    : ""}
                </small>
              </article>

              <div className="action-grid">
                {llmRemediation.priority_actions.map(
                  (action, index) => (
                    <article
                      className="action-card"
                      key={`${action.title}-${index}`}
                    >
                      <div className="action-rank">
                        {index + 1}
                      </div>
                      <div>
                        <h3>
                          {action.title}
                        </h3>
                        <p>
                          {action.rationale}
                        </p>
                        <div className="action-meta">
                          <span>
                            {action.owner}
                          </span>
                          <span>
                            {action.control}
                          </span>
                          <span>
                            Effort: {action.effort}
                          </span>
                        </div>
                        <ul>
                          {action.next_steps.map(
                            (step) => (
                              <li key={step}>
                                {step}
                              </li>
                            )
                          )}
                        </ul>
                      </div>
                    </article>
                  )
                )}
              </div>

              <article className="residual-card">
                <b>
                  Residual Risk
                </b>
                <p>
                  {llmRemediation.residual_risk}
                </p>
              </article>

            </div>
          )}

        </section>

      </section>

    </main>
  );
}

function downloadBlob(
  content,
  filename,
  type
) {

  const blob =
    content instanceof Blob
      ? content
      : new Blob(
          [content],
          { type }
        );

  const url =
    URL.createObjectURL(blob);

  const link =
    document.createElement("a");

  link.href = url;

  link.download = filename;

  document.body.appendChild(link);

  link.click();

  link.remove();

  URL.revokeObjectURL(url);
}

function buildGraphLayout(network) {
  const nodeCount =
    network?.nodes?.length ?? 0;

  const edgeCount =
    network?.edges?.length ?? 0;

  if (nodeCount >= 14 || edgeCount >= 18) {
    return {
      name: "cose",
      animate: false,
      fit: true,
      padding: 80,
      nodeRepulsion: 16000,
      nodeOverlap: 24,
      idealEdgeLength: 170,
      edgeElasticity: 90,
      nestingFactor: 1.2,
      gravity: 0.18,
      numIter: 2200,
      initialTemp: 180,
      coolingFactor: 0.92,
      minTemp: 1
    };
  }

  return {
    name: "breadthfirst",
    directed: true,
    padding: 70,
    spacingFactor: nodeCount > 8 ? 2.1 : 1.6,
    avoidOverlap: true
  };
}

createRoot(
  document.getElementById("root")
).render(<App />);
