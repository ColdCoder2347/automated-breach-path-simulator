import React from "react";

export function ReportActions({ disabled, onExportJson, onExportPdf, onUpload }) {
  return (
    <section className="panel">
      <h2>Data</h2>
      <label className="file-picker">
        Upload topology JSON
        <input type="file" accept="application/json" onChange={onUpload} />
      </label>
      <div className="button-row">
        <button onClick={onExportJson} disabled={disabled}>Export JSON</button>
        <button onClick={onExportPdf} disabled={disabled}>Export PDF</button>
      </div>
    </section>
  );
}
