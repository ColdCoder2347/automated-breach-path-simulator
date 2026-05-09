import React from "react";

export function SimulationControls({
  algorithm,
  criticalAsset,
  criticalAssets,
  entries,
  entryPoint,
  hasPath,
  onAlgorithmChange,
  onCriticalAssetChange,
  onEntryPointChange,
  onPlay,
  onRun
}) {
  return (
    <section className="panel">
      <h2>Simulation</h2>
      <label>
        Algorithm
        <select value={algorithm} onChange={(event) => onAlgorithmChange(event.target.value)}>
          <option value="dijkstra">Dijkstra</option>
          <option value="bfs">BFS</option>
          <option value="dfs">DFS</option>
        </select>
      </label>
      <label>
        Entry point
        <select value={entryPoint} onChange={(event) => onEntryPointChange(event.target.value)}>
          {entries.map((node) => <option key={node.id} value={node.id}>{node.label}</option>)}
        </select>
      </label>
      <label>
        Critical asset
        <select value={criticalAsset} onChange={(event) => onCriticalAssetChange(event.target.value)}>
          {criticalAssets.map((node) => <option key={node.id} value={node.id}>{node.label}</option>)}
        </select>
      </label>
      <button className="primary" onClick={onRun}>Run analysis</button>
      <button onClick={onPlay} disabled={!hasPath}>Play active path</button>
    </section>
  );
}
