import React from "react";

export function MitreChainPanel({ chain, currentStep }) {
  return (
    <section className="intelligence-panel">
      <h2>MITRE ATT&CK Chain</h2>
      {chain?.length ? (
        <ol className="mitre-chain">
          {chain.map((item, index) => (
            <li key={`${item}-${index}`} className={currentStep?.mitre_id && item.includes(currentStep.mitre_id) ? "active" : ""}>
              {item}
            </li>
          ))}
        </ol>
      ) : (
        <p>Run analysis to enrich attack steps with MITRE tactics and techniques.</p>
      )}
    </section>
  );
}
