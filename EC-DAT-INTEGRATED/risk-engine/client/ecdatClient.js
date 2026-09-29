/**
 * ECDAT API client -- single-file wrapper around every backend endpoint.
 *
 * Works in the browser (React, plain JS) and in Node 18+ (native fetch).
 * No dependencies. Import this instead of hand-writing fetch() calls
 * against the API in three different components.
 *
 * ---------------------------------------------------------------------
 * USAGE
 * ---------------------------------------------------------------------
 *
 *   import { createECDATClient } from "./ecdatClient.js";
 *
 *   const ecdat = createECDATClient({
 *     baseUrl: "http://localhost:5000",       // no trailing slash
 *     apiKey: "ecdat-dev-key-change-me",       // matches ECDAT_API_KEYS on the server
 *   });
 *
 *   const scan = await ecdat.scanSample();
 *   console.log(scan.agility_score.score);
 *
 *   const risks = await ecdat.getRisk(scan.scan_id);
 *   const blob = await ecdat.getReportPdfBlob(scan.scan_id);
 *
 * Every method returns a Promise. On a non-2xx response, the Promise
 * rejects with an ECDATApiError carrying `.status`, `.message`, and
 * `.details` (the field-level validation errors, when present) --
 * check `error.details` before showing a generic failure message.
 *
 * ---------------------------------------------------------------------
 * REACT EXAMPLE
 * ---------------------------------------------------------------------
 *
 *   const ecdat = createECDATClient({ baseUrl: API_URL, apiKey: API_KEY });
 *
 *   function useScan(scanId) {
 *     const [report, setReport] = useState(null);
 *     const [error, setError] = useState(null);
 *     useEffect(() => {
 *       if (!scanId) return;
 *       ecdat.getScan(scanId).then(setReport).catch(setError);
 *     }, [scanId]);
 *     return { report, error };
 *   }
 */

export class ECDATApiError extends Error {
  constructor(message, { status, details } = {}) {
    super(message);
    this.name = "ECDATApiError";
    this.status = status ?? null;
    this.details = details ?? [];
  }
}

/**
 * @param {Object} config
 * @param {string} config.baseUrl - e.g. "http://localhost:5000" (no trailing slash)
 * @param {string} config.apiKey  - value sent as the X-API-Key header
 * @param {typeof fetch} [config.fetchImpl] - override fetch (mainly for tests)
 */
export function createECDATClient({ baseUrl, apiKey, fetchImpl }) {
  if (!baseUrl) throw new Error("createECDATClient: 'baseUrl' is required.");
  if (!apiKey) throw new Error("createECDATClient: 'apiKey' is required.");

  const _fetch = fetchImpl || (typeof fetch !== "undefined" ? fetch : null);
  if (!_fetch) {
    throw new Error(
      "No fetch implementation found. In Node < 18, pass { fetchImpl } " +
      "(e.g. from 'node-fetch'). Node 18+ and all modern browsers have fetch built in."
    );
  }

  /**
   * Core request helper. Handles auth header, JSON encode/decode,
   * and turns non-2xx responses into a structured ECDATApiError so
   * callers don't need to inspect response.ok themselves.
   */
  async function _request(path, { method = "GET", body, responseType = "json" } = {}) {
    const headers = { "X-API-Key": apiKey };
    let payload;
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(body);
    }

    let res;
    try {
      res = await _fetch(`${baseUrl}${path}`, { method, headers, body: payload });
    } catch (networkErr) {
      throw new ECDATApiError(
        `Network error calling ${method} ${path}: ${networkErr.message}. ` +
        `Is the server running at ${baseUrl}?`,
        { status: null }
      );
    }

    if (res.status === 429) {
      const retryAfter = res.headers.get("Retry-After");
      throw new ECDATApiError(
        `Rate limited on ${method} ${path}. Retry after ${retryAfter ?? "a few"}s.`,
        { status: 429 }
      );
    }

    if (!res.ok) {
      let message = `${method} ${path} failed with HTTP ${res.status}`;
      let details = [];
      try {
        const errBody = await res.json();
        message = errBody.error || message;
        details = errBody.details || [];
      } catch {
        /* response wasn't JSON (e.g. a raw 404/500 HTML page) -- fall back to the generic message */
      }
      throw new ECDATApiError(message, { status: res.status, details });
    }

    if (responseType === "blob") return res.blob();
    if (responseType === "text") return res.text();
    if (res.status === 204) return null; // no content
    return res.json();
  }

  return {
    // ---- Health & docs ----------------------------------------------------

    /** GET /api/health -- no auth required. Returns { status: "ok" }. */
    health: () => _request("/api/health"),

    /** URL of the interactive Swagger UI docs page (open directly in a browser tab). */
    docsUrl: () => `${baseUrl}/api/docs`,

    /** GET /api/openapi.json -- the raw OpenAPI 3.0 spec, if you want to codegen a client instead. */
    getOpenApiSpec: () => _request("/api/openapi.json"),

    // ---- Scans --------------------------------------------------------------

    /**
     * POST /api/scans -- run a new scan against your own CBOM findings.
     * @param {Array<Object>} cbom - raw artefact objects (see README's CBOM schema)
     * @param {Object} [opts]
     * @param {number} [opts.yearsToCrqc=12] - Z in Mosca's theorem
     * @param {boolean} [opts.skipDedup=false]
     */
    createScan: (cbom, { yearsToCrqc = 12, skipDedup = false } = {}) =>
      _request("/api/scans", {
        method: "POST",
        body: { cbom, years_to_crqc: yearsToCrqc, skip_dedup: skipDedup },
      }),

    /**
     * POST /api/scans/sample -- run a scan against the built-in 12-artefact
     * sample CBOM. Use this to build/demo the frontend before Dev 1's
     * scanner is wired up -- the response shape is identical to createScan().
     */
    scanSample: ({ yearsToCrqc = 12 } = {}) =>
      _request("/api/scans/sample", { method: "POST", body: { years_to_crqc: yearsToCrqc } }),

    /** GET /api/scans -- scan history summaries, most recent first. */
    listScans: () => _request("/api/scans"),

    /** GET /api/scans/{id} -- full report, with any triage overrides applied. */
    getScan: (scanId) => _request(`/api/scans/${encodeURIComponent(scanId)}`),

    // ---- Individual report sections (all mirror fields already on getScan()) ----

    getCbom: (scanId) => _request(`/api/scans/${encodeURIComponent(scanId)}/cbom`),
    getRisk: (scanId) => _request(`/api/scans/${encodeURIComponent(scanId)}/risk`),
    getRecommendations: (scanId) => _request(`/api/scans/${encodeURIComponent(scanId)}/recommendations`),
    getAgilityScore: (scanId) => _request(`/api/scans/${encodeURIComponent(scanId)}/agility-score`),
    getRoadmap: (scanId) => _request(`/api/scans/${encodeURIComponent(scanId)}/roadmap`),
    getHndl: (scanId) => _request(`/api/scans/${encodeURIComponent(scanId)}/hndl`),
    getBlastRadius: (scanId) => _request(`/api/scans/${encodeURIComponent(scanId)}/blast-radius`),
    getRegulatory: (scanId) => _request(`/api/scans/${encodeURIComponent(scanId)}/regulatory`),
    getCveFindings: (scanId) => _request(`/api/scans/${encodeURIComponent(scanId)}/cve-findings`),
    getCertificates: (scanId) => _request(`/api/scans/${encodeURIComponent(scanId)}/certificates`),

    // ---- Standardised format exports ----------------------------------------

    /** GET /api/scans/{id}/cyclonedx -- CycloneDX 1.6 CBOM export as a JS object. */
    getCyclonedx: (scanId) => _request(`/api/scans/${encodeURIComponent(scanId)}/cyclonedx`),

    /**
     * GET /api/scans/{id}/report.pdf -- returns a Blob you can feed to
     * URL.createObjectURL() for an <a download> link or an <iframe> preview.
     */
    getReportPdfBlob: (scanId) =>
      _request(`/api/scans/${encodeURIComponent(scanId)}/report.pdf`, { responseType: "blob" }),

    /**
     * Convenience: trigger a browser download of the PDF report directly
     * (creates a temporary <a> element and clicks it). Browser-only --
     * do not call this from Node.
     */
    async downloadReportPdf(scanId, filename) {
      const blob = await this.getReportPdfBlob(scanId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename || `ecdat_report_${scanId}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    },

    // ---- Trend / diff (USP) --------------------------------------------------

    /** GET /api/scans/{id}/trend -- diff vs. the immediately previous scan. */
    getTrend: (scanId) => _request(`/api/scans/${encodeURIComponent(scanId)}/trend`),

    /** GET /api/scans/{olderId}/diff/{newerId} -- diff between two specific scans. */
    getDiff: (olderId, newerId) =>
      _request(`/api/scans/${encodeURIComponent(olderId)}/diff/${encodeURIComponent(newerId)}`),

    // ---- What-if simulator (USP) ---------------------------------------------

    /**
     * POST /api/scans/{id}/simulate -- project the Agility Score and risk
     * counts if the given artefact IDs were remediated. Nothing is persisted.
     * @param {string} scanId
     * @param {string[]} remediatedArtefactIds
     */
    simulate: (scanId, remediatedArtefactIds) =>
      _request(`/api/scans/${encodeURIComponent(scanId)}/simulate`, {
        method: "POST",
        body: { remediated_artefact_ids: remediatedArtefactIds },
      }),

    // ---- Manual triage / override --------------------------------------------

    /**
     * POST /api/scans/{id}/triage -- set a manual override for one artefact.
     * @param {string} scanId
     * @param {Object} override
     * @param {string} override.artefactId
     * @param {"accepted_risk"|"false_positive"|"confirmed"} override.status
     * @param {string} override.justification - required, non-empty
     * @param {string} override.reviewer
     */
    setTriage: (scanId, { artefactId, status, justification, reviewer }) =>
      _request(`/api/scans/${encodeURIComponent(scanId)}/triage`, {
        method: "POST",
        body: { artefact_id: artefactId, status, justification, reviewer },
      }),

    /** GET /api/scans/{id}/triage -- current overrides for a scan, keyed by artefact_id. */
    getTriage: (scanId) => _request(`/api/scans/${encodeURIComponent(scanId)}/triage`),

    // ---- CI/CD gate template --------------------------------------------------

    /**
     * GET /api/scans/{id}/ci-gate.yml -- generated GitHub Actions workflow
     * (as a YAML string) that fails a build on new non-PQC crypto.
     */
    getCiGateYaml: (scanId, { failOnTier = "Critical", apiBaseUrl } = {}) => {
      const params = new URLSearchParams({ fail_on_tier: failOnTier });
      if (apiBaseUrl) params.set("api_base_url", apiBaseUrl);
      return _request(`/api/scans/${encodeURIComponent(scanId)}/ci-gate.yml?${params}`, { responseType: "text" });
    },

    // ---- Tamper-evident signing -------------------------------------------------

    /** GET /api/scans/{id}/signature -- signs the current report; returns the signature object. */
    getSignature: (scanId) => _request(`/api/scans/${encodeURIComponent(scanId)}/signature`),

    /**
     * POST /api/scans/{id}/verify -- verify a report+signature pair.
     * @param {string} scanId
     * @param {Object} signature - the object returned by getSignature()
     * @returns {Promise<{valid: boolean}>}
     */
    verify: (scanId, signature) =>
      _request(`/api/scans/${encodeURIComponent(scanId)}/verify`, { method: "POST", body: { signature } }),
  };
}

export default createECDATClient;
