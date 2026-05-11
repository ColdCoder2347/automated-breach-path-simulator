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
  // SAMPLE NETWORK
  // =====================================================

  useEffect(() => {

    axios
      .get(`${API_BASE}/sample`)
      .then((response) => {

        setNetwork(response.data);

        setStatus(
          "Sample topology loaded"
        );

      })
      .catch(() => {

        setStatus(
          "Backend not reachable"
        );

      });

  }, []);

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

      layout: {
        name: "breadthfirst",
        directed: true,
        padding: 40,
        spacingFactor: 1.4
      },

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

          <button
            onClick={runSimulation}
          >
            Run Simulation
          </button>

          <button
            onClick={exportJson}
          >
            Export JSON
          </button>

          <button
            onClick={exportPdf}
          >
            Export PDF
          </button>

        </section>

      </aside>

      <section className="workspace">

        <div
          className="graph-area"
          ref={cyRef}
        />

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

createRoot(
  document.getElementById("root")
).render(<App />);
