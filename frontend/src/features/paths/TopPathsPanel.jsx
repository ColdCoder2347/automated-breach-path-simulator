import React from "react";

export function TopPathsPanel({ selectedPath, topPaths, onSelectPath }) {
  const paths = topPaths?.paths ?? [];

  return (
    <section className="intelligence-panel">
      <h2>Top Attack Paths</h2>
      {paths.length ? (
        <div className="path-stack">
          {paths.map((path) => (
            <button
              key={path.rank}
              className={selectedPath?.rank === path.rank ? "path-card selected" : "path-card"}
              onClick={() => onSelectPath(path)}
            >
              <span>#{path.rank} | Risk {path.risk_score}/100</span>
              <b>{path.path.join(" -> ")}</b>
              <small>{path.hop_count} hops | Weight {path.total_weight}</small>
            </button>
          ))}
        </div>
      ) : (
        <p>Run analysis to rank likely local attack paths.</p>
      )}
    </section>
  );
}
