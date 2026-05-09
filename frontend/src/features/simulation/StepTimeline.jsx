import React from "react";

export function StepTimeline({ activeStep, currentStep, steps, onStepSelect }) {
  return (
    <section className="intelligence-panel">
      <h2>Step-by-step Breach</h2>
      {currentStep ? (
        <div className="step-focus">
          <b>{activeStep + 1}. {currentStep.label}</b>
          <span>{currentStep.edge_label ? `Reached via ${currentStep.edge_label} | CVSS ${currentStep.cvss}` : "Initial foothold"}</span>
          {currentStep.mitre_tactic && (
            <em>{currentStep.mitre_tactic}: {currentStep.mitre_technique} {currentStep.mitre_id ? `(${currentStep.mitre_id})` : ""}</em>
          )}
        </div>
      ) : (
        <p>Run a simulation to inspect attacker movement.</p>
      )}
      <div className="step-list">
        {steps.map((step, index) => (
          <button key={`${step.node_id}-${index}`} className={index === activeStep ? "selected" : ""} onClick={() => onStepSelect(index)}>
            {index + 1}
          </button>
        ))}
      </div>
    </section>
  );
}
