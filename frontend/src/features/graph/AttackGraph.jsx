import { useEffect, useMemo, useRef } from "react";
import cytoscape from "cytoscape";

export function AttackGraph({ activePath, activeStep, network }) {
  const cyRef = useRef(null);
  const graphRef = useRef(null);

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
      style: graphStyle
    });
  }, [elements]);

  useEffect(() => {
    const graph = graphRef.current;
    if (!graph) return;
    graph.elements().removeClass("path-node path-edge active-node");
    activePath.forEach((id, index) => {
      graph.getElementById(id).addClass(index === activeStep ? "active-node" : "path-node");
      if (index > 0) {
        graph.getElementById(`${activePath[index - 1]}-${id}`).addClass("path-edge");
      }
    });
  }, [activePath, activeStep]);

  return <div className="graph-area" ref={cyRef} />;
}

const graphStyle = [
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
];
