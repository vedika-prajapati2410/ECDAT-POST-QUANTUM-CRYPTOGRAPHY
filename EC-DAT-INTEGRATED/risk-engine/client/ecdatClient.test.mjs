/**
 * Integration test for ecdatClient.js -- exercises every method against a
 * REAL running server (not mocked), including the error-handling paths.
 *
 * Prerequisites: the ECDAT server must already be running.
 *   Terminal 1:  python3 run.py
 *   Terminal 2:  node client/ecdatClient.test.mjs
 *
 * Requires Node 18+ (for native fetch). No other dependencies.
 */
import { createECDATClient, ECDATApiError } from "./ecdatClient.js";

const BASE_URL = process.env.ECDAT_BASE_URL || "http://localhost:5000";
const API_KEY = process.env.ECDAT_API_KEY || "ecdat-dev-key-change-me";

const ecdat = createECDATClient({ baseUrl: BASE_URL, apiKey: API_KEY });

let passed = 0;
let failed = 0;

function assert(cond, msg) {
  if (cond) {
    console.log("PASS:", msg);
    passed++;
  } else {
    console.log("FAIL:", msg);
    failed++;
  }
}

async function main() {
  try {
    await ecdat.health();
  } catch (e) {
    console.error(
      `\nCouldn't reach the server at ${BASE_URL}. Is it running? (python3 run.py)\n` + e.message
    );
    process.exit(1);
  }

  const health = await ecdat.health();
  assert(health.status === "ok", "health check returns ok");

  const scan = await ecdat.scanSample({ yearsToCrqc: 12 });
  assert(Boolean(scan.scan_id) && scan.artefact_count > 0, "scanSample returns a real report with scan_id");
  const scanId = scan.scan_id;

  const full = await ecdat.getScan(scanId);
  assert(full.scan_id === scanId, "getScan retrieves the same scan");

  const risk = await ecdat.getRisk(scanId);
  assert(Array.isArray(risk) && risk.length === full.artefact_count, "getRisk returns per-artefact risk array");

  const agility = await ecdat.getAgilityScore(scanId);
  assert(typeof agility.score === "number", "getAgilityScore returns a numeric score");

  const roadmap = await ecdat.getRoadmap(scanId);
  assert(Array.isArray(roadmap) && roadmap.length === 4, "getRoadmap returns 4 phases");

  const hndl = await ecdat.getHndl(scanId);
  assert(typeof hndl.total_exposed_gb === "number", "getHndl returns exposure GB");

  const blast = await ecdat.getBlastRadius(scanId);
  assert(Boolean(blast.graph) && Array.isArray(blast.graph.nodes), "getBlastRadius returns a graph");

  const reg = await ecdat.getRegulatory(scanId);
  assert(Array.isArray(reg), "getRegulatory returns flags array");

  const cve = await ecdat.getCveFindings(scanId);
  assert(Array.isArray(cve), "getCveFindings returns array");

  const certs = await ecdat.getCertificates(scanId);
  assert(Array.isArray(certs), "getCertificates returns array");

  const cdx = await ecdat.getCyclonedx(scanId);
  assert(cdx.bomFormat === "CycloneDX", "getCyclonedx returns a real CycloneDX object");

  const pdfBlob = await ecdat.getReportPdfBlob(scanId);
  assert(pdfBlob.size > 1000, `getReportPdfBlob returns a real PDF blob (size=${pdfBlob.size})`);

  const trend = await ecdat.getTrend(scanId);
  assert(trend.message !== undefined || trend.newly_introduced !== undefined, "getTrend responds");

  const criticalIds = risk.filter((r) => r.risk_tier === "Critical").map((r) => r.artefact_id);
  const sim = await ecdat.simulate(scanId, criticalIds);
  assert("projected_agility_score" in sim, "simulate returns a projected_agility_score");

  const triageResult = await ecdat.setTriage(scanId, {
    artefactId: full.cbom[0].id,
    status: "accepted_risk",
    justification: "integration test via JS client",
    reviewer: "js-client-test",
  });
  assert(triageResult.status === "accepted_risk", "setTriage sets an override");

  const triageList = await ecdat.getTriage(scanId);
  assert(Object.keys(triageList).includes(full.cbom[0].id), "getTriage lists the override we just set");

  const yamlText = await ecdat.getCiGateYaml(scanId);
  assert(typeof yamlText === "string" && yamlText.includes("name:"), "getCiGateYaml returns YAML text");

  const sig = await ecdat.getSignature(scanId);
  assert(Boolean(sig.algorithm), "getSignature returns a signature object");

  const verifyResult = await ecdat.verify(scanId, sig);
  assert(verifyResult.valid === true, "verify confirms the signature is valid");

  // --- error handling ---

  try {
    await ecdat.getScan("does-not-exist");
    assert(false, "getScan on unknown id should have rejected");
  } catch (e) {
    assert(e instanceof ECDATApiError && e.status === 404, "getScan on unknown id rejects with ECDATApiError status 404");
  }

  try {
    await ecdat.createScan([{ name: "no-id" }]);
    assert(false, "createScan with invalid cbom should have rejected");
  } catch (e) {
    assert(e instanceof ECDATApiError && e.status === 422 && e.details.length > 0, "createScan validation error surfaces .details");
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

main();
