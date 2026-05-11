import axios from "axios";

export const API_BASE = window.breachSimulator?.apiBaseUrl ?? "http://127.0.0.1:8765";

export async function analyzeNetwork(payload) {
  const response = await axios.post(`${API_BASE}/analyze`, payload);
  return response.data;
}

export async function getTopPaths(payload) {
  const response = await axios.post(`${API_BASE}/paths/top`, payload);
  return response.data;
}

export async function recommendRemediation(payload) {
  const response = await axios.post(`${API_BASE}/remediation/recommend`, payload);
  return response.data;
}

export async function validateTopology(network) {
  const response = await axios.post(`${API_BASE}/validate-topology`, network);
  return response.data;
}

export async function exportJsonReport(payload) {
  const response = await axios.post(`${API_BASE}/report/json`, payload);
  return response.data;
}

export async function exportPdfReport(payload) {
  const response = await axios.post(`${API_BASE}/report/pdf`, payload, { responseType: "blob" });
  return response.data;
}
