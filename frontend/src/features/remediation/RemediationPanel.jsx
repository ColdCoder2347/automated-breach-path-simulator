import React from "react";

export function RemediationPanel({ remediation }) {
  const recommendations = remediation?.recommendations ?? [];

  return (
    <section className="intelligence-panel">
      <h2>Remediation Priorities</h2>
      {recommendations.length ? (
        <div className="recommendation-list">
          {recommendations.map((item) => (
            <article key={item.priority} className="recommendation">
              <div>
                <span>Priority {item.priority}</span>
                <b>{item.title}</b>
              </div>
              <p>{item.recommendation}</p>
              <small>{item.target_id} | affects {item.affected_paths} paths | risk reduction {item.estimated_risk_reduction}</small>
            </article>
          ))}
        </div>
      ) : (
        <p>Run analysis to generate remediation recommendations from ranked paths.</p>
      )}
    </section>
  );
}
