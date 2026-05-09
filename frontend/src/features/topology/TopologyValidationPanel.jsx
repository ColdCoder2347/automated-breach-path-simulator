export function TopologyValidationPanel({ compact = false, validation }) {
  const warnings = validation?.warnings ?? [];
  const errors = validation?.errors ?? [];
  const visibleIssues = [...errors, ...warnings].slice(0, compact ? 3 : 8);

  return (
    <section className={compact ? "panel validation compact" : "intelligence-panel validation"}>
      <h2>Topology Validation</h2>
      {validation ? (
        <>
          <div className="validation-summary">
            <span className={validation.valid ? "status-good" : "status-bad"}>
              {validation.valid ? "Valid" : "Needs attention"}
            </span>
            <span>{validation.summary.errors} errors</span>
            <span>{validation.summary.warnings} warnings</span>
          </div>
          <ul>
            {visibleIssues.map((issue) => (
              <li key={`${issue.code}-${issue.target}-${issue.message}`}>
                <b>{issue.code}</b> {issue.message}
              </li>
            ))}
            {!visibleIssues.length && <li>No topology issues detected.</li>}
          </ul>
        </>
      ) : (
        <p>No topology has been validated yet.</p>
      )}
    </section>
  );
}
