/**
 * Minimal React usage example for ecdatClient.js -- not a runnable app,
 * just a copy-from reference for the frontend dev. Assumes Vite/CRA-style
 * tooling where ES module imports and JSX work out of the box.
 *
 * Wire API_URL / API_KEY to your actual .env values before using this for real.
 */
import { useEffect, useState } from "react";
import { createECDATClient } from "./ecdatClient.js";

const ecdat = createECDATClient({
  baseUrl: import.meta.env?.VITE_ECDAT_API_URL || "http://localhost:5000",
  apiKey: import.meta.env?.VITE_ECDAT_API_KEY || "ecdat-dev-key-change-me",
});

/** Runs a sample scan on mount and shows the headline numbers. Swap
 * `ecdat.scanSample()` for `ecdat.createScan(yourCbom)` once Dev 1's
 * scanner is producing real findings. */
export function DashboardExample() {
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    ecdat
      .scanSample()
      .then(setReport)
      .catch(setError)
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <p>Scanning...</p>;
  if (error) return <p style={{ color: "red" }}>Error: {error.message}</p>;

  return (
    <div>
      <h2>Crypto-Agility Score: {report.agility_score.score} ({report.agility_score.grade})</h2>
      <p>{report.agility_score.maturity_level_name}</p>
      <p>{report.artefact_count} artefacts scanned</p>
      <ul>
        {Object.entries(report.risk_tier_counts).map(([tier, count]) => (
          <li key={tier}>{tier}: {count}</li>
        ))}
      </ul>
      <a href="#" onClick={(e) => { e.preventDefault(); ecdat.downloadReportPdf(report.scan_id); }}>
        Download PDF report
      </a>
    </div>
  );
}

/** Example: what-if simulator UI -- select artefacts, see the projected score. */
export function WhatIfExample({ scanId, riskItems }) {
  const [selected, setSelected] = useState([]);
  const [projection, setProjection] = useState(null);

  async function runSimulation() {
    const result = await ecdat.simulate(scanId, selected);
    setProjection(result);
  }

  return (
    <div>
      {riskItems.map((r) => (
        <label key={r.artefact_id} style={{ display: "block" }}>
          <input
            type="checkbox"
            checked={selected.includes(r.artefact_id)}
            onChange={(e) =>
              setSelected((prev) =>
                e.target.checked ? [...prev, r.artefact_id] : prev.filter((id) => id !== r.artefact_id)
              )
            }
          />
          {r.artefact_id} ({r.risk_tier})
        </label>
      ))}
      <button onClick={runSimulation}>Simulate remediation</button>
      {projection && (
        <p>
          Score would go from {projection.current_agility_score} to{" "}
          {projection.projected_agility_score} (+{projection.score_improvement})
        </p>
      )}
    </div>
  );
}
