"""
REST API layer (Flask).

This is the contract with the frontend dev and with Dev 1's scanner.
All endpoints return JSON except the PDF/YAML export endpoints, which
return their native content types. CORS is wide open for hackathon
convenience but every mutating/read endpoint under /api/ requires an
API key (see `_require_api_key` below) -- lock down further before
any real deployment.

Hardening on top of the core pipeline:
  - Input validation (app/validation.py) rejects malformed CBOM with
    detailed per-field errors before it ever reaches the pipeline,
    and caps a single scan at 5000 artefacts.
  - Request bodies are capped at 15 MB (app.config MAX_CONTENT_LENGTH).
  - Per-API-key rate limiting (app/rate_limit.py): 15/min for scan
    creation, 120/min for everything else.
  - Interactive API docs at GET /api/docs (Swagger UI) and the raw
    spec at GET /api/openapi.json -- both public, no API key needed,
    since they're documentation rather than data.

Endpoint summary
-----------------
Auth:      all /api/* except /api/health, /api/openapi.json, /api/docs
           require header  X-API-Key: <key>. Dev default key is
           printed to stdout on startup; override with the
           ECDAT_API_KEYS environment variable (comma-separated).

POST /api/scans                      -> run a new scan
POST /api/scans/sample                -> run a scan against the built-in sample CBOM
GET  /api/scans                       -> list scan history (summaries)
GET  /api/scans/<id>                   -> full report
GET  /api/scans/<id>/cbom              -> CBOM inventory
GET  /api/scans/<id>/risk              -> risk assessment
GET  /api/scans/<id>/recommendations   -> recommendations
GET  /api/scans/<id>/agility-score     -> Crypto-Agility Score + maturity level
GET  /api/scans/<id>/roadmap           -> migration roadmap
GET  /api/scans/<id>/hndl              -> harvest-now-decrypt-later exposure
GET  /api/scans/<id>/blast-radius      -> dependency blast radius
GET  /api/scans/<id>/regulatory        -> Indian regulatory/compliance triage flags
GET  /api/scans/<id>/cve-findings      -> CVE cross-reference findings (libraries)
GET  /api/scans/<id>/certificates      -> certificate deep-analysis findings
GET  /api/scans/<id>/cyclonedx         -> CycloneDX 1.6 CBOM export (JSON)
GET  /api/scans/<id>/report.pdf        -> human-readable PDF report
GET  /api/scans/<id>/trend             -> diff vs. the immediately previous scan
GET  /api/scans/<older>/diff/<newer>   -> diff between two specific scans
POST /api/scans/<id>/simulate          -> what-if remediation simulator
POST /api/scans/<id>/triage            -> set a manual triage override
GET  /api/scans/<id>/triage            -> list current overrides for a scan
GET  /api/scans/<id>/ci-gate.yml       -> generated GitHub Actions gate workflow
GET  /api/scans/<id>/signature         -> tamper-evident signature for the report
POST /api/scans/<id>/verify            -> verify a report+signature pair
GET  /api/health                       -> liveness check (no auth required)
GET  /api/openapi.json                 -> OpenAPI 3.0 spec (no auth required)
GET  /api/docs                         -> interactive Swagger UI (no auth required)
"""

import os
import io
import tempfile

from flask import Flask, request, jsonify, send_file, Response

from app.pipeline import run_pipeline
from app.sample_cbom import SAMPLE_CBOM
from app import storage
from app.cyclonedx_export import build_cyclonedx_cbom
from app.pdf_report import build_pdf_report
from app.trend_analysis import diff_reports
from app.simulator import simulate_remediation
from app.triage import apply_overrides, make_override
from app.ci_cd_template import generate_github_action
from app.report_signing import sign_report, verify_report
from app.validation import validate_raw_cbom, ValidationError
from app.cbom_adapter import adapt_cyclonedx_cbom
from app.rate_limit import check_rate_limit
from app.openapi_spec import build_openapi_spec

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 15 * 1024 * 1024  # 15 MB request body cap -- a CBOM is JSON text, this is generous

# --- Auth ---
# Dev default so the demo works out of the box; ALWAYS override via
# environment variable before deploying anywhere real.
_DEFAULT_DEV_KEY = "ecdat-dev-key-change-me"
_API_KEYS = set(
    k.strip() for k in os.environ.get("ECDAT_API_KEYS", _DEFAULT_DEV_KEY).split(",") if k.strip()
)
if _API_KEYS == {_DEFAULT_DEV_KEY}:
    print(f"[ECDAT] WARNING: using default dev API key '{_DEFAULT_DEV_KEY}'. "
          f"Set ECDAT_API_KEYS env var before deploying.", flush=True)

_HEAVY_ROUTES = {("/api/scans", "POST"), ("/api/scans/sample", "POST")}


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key"
    return response


@app.route("/api/<path:_any>", methods=["OPTIONS"])
def cors_preflight(_any):
    return "", 204


@app.before_request
def _require_api_key():
    if request.method == "OPTIONS" or request.path in ("/api/health", "/api/openapi.json", "/api/docs"):
        return None
    if not request.path.startswith("/api/"):
        return None
    supplied = request.headers.get("X-API-Key", "")
    if supplied not in _API_KEYS:
        return jsonify({"error": "Missing or invalid X-API-Key header."}), 401
    return None


@app.before_request
def _enforce_rate_limit():
    if request.method == "OPTIONS" or request.path in ("/api/health", "/api/openapi.json", "/api/docs"):
        return None
    if not request.path.startswith("/api/"):
        return None
    api_key = request.headers.get("X-API-Key", "")
    bucket = "heavy" if (request.path, request.method) in _HEAVY_ROUTES else "default"
    allowed, retry_after = check_rate_limit(api_key, bucket)
    if not allowed:
        resp = jsonify({"error": f"Rate limit exceeded for this endpoint. Retry after {retry_after}s."})
        resp.headers["Retry-After"] = str(retry_after)
        return resp, 429
    return None


@app.errorhandler(413)
def _too_large(_exc):
    return jsonify({"error": "Request body too large (max 15 MB). Split into multiple scans."}), 413


def _error(message, status=400):
    return jsonify({"error": message}), status


def _get_or_404(scan_id):
    return storage.get_scan(scan_id)


def _sub_report(scan_id, key):
    report = _get_or_404(scan_id)
    if report is None:
        return _error("Scan not found.", status=404)
    return jsonify(report[key])


def _report_with_overrides(scan_id):
    """Apply any stored triage overrides to a fresh copy of the report before returning it."""
    report = _get_or_404(scan_id)
    if report is None:
        return None
    overrides = storage.get_overrides(scan_id)
    if not overrides:
        return report
    report = dict(report)
    report["risks"] = apply_overrides(report["risks"], overrides)
    return report


# --- Health (no auth) ---

@app.get("/api/health")
def health():
    return jsonify({"status": "ok"})


# --- Scans ---
@app.post("/api/scans")
def create_scan():
    body = request.get_json(silent=True) or {}

    raw_cyclonedx_cbom = body.get("cbom")

    years_to_crqc = body.get(
        "years_to_crqc",
        12.0
    )

    skip_dedup = bool(
        body.get(
            "skip_dedup",
            False
        )
    )
    try:
        raw_cbom = adapt_cyclonedx_cbom(
            raw_cyclonedx_cbom
        )

        validate_raw_cbom(
            raw_cbom
        )

    except ValidationError as exc:
        return jsonify(
            exc.to_dict()
        ), 422

    except ValueError as exc:
        return jsonify(
            {
                "error": str(exc)
            }
        ), 422

    try:
        report = run_pipeline(
            raw_cbom,
            years_to_crqc=float(
                years_to_crqc
            ),
            skip_dedup=skip_dedup
        )

    except Exception as exc:
        return _error(
            f"Failed to process CBOM: {exc}",
            status=422
        )

    storage.save_scan(
        report
    )

    return jsonify(
        report
    ), 201



@app.post("/api/scans/sample")
def create_sample_scan():
    body = request.get_json(silent=True) or {}
    years_to_crqc = body.get("years_to_crqc", 12.0)
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=float(years_to_crqc))
    storage.save_scan(report)
    return jsonify(report), 201


@app.get("/api/scans")
def scan_history():
    return jsonify(storage.list_scans())


@app.get("/api/scans/<scan_id>")
def full_report(scan_id):
    report = _report_with_overrides(scan_id)
    if report is None:
        return _error("Scan not found.", status=404)
    return jsonify(report)


@app.get("/api/scans/<scan_id>/cbom")
def cbom(scan_id):
    return _sub_report(scan_id, "cbom")


@app.get("/api/scans/<scan_id>/risk")
def risk(scan_id):
    report = _report_with_overrides(scan_id)
    if report is None:
        return _error("Scan not found.", status=404)
    return jsonify(report["risks"])


@app.get("/api/scans/<scan_id>/recommendations")
def recommendations(scan_id):
    return _sub_report(scan_id, "recommendations")


@app.get("/api/scans/<scan_id>/agility-score")
def agility_score(scan_id):
    return _sub_report(scan_id, "agility_score")


@app.get("/api/scans/<scan_id>/roadmap")
def roadmap(scan_id):
    return _sub_report(scan_id, "migration_roadmap")


@app.get("/api/scans/<scan_id>/hndl")
def hndl(scan_id):
    return _sub_report(scan_id, "harvest_now_decrypt_later")


@app.get("/api/scans/<scan_id>/blast-radius")
def blast_radius(scan_id):
    return _sub_report(scan_id, "dependency_blast_radius")


@app.get("/api/scans/<scan_id>/regulatory")
def regulatory(scan_id):
    return _sub_report(scan_id, "regulatory_flags")


@app.get("/api/scans/<scan_id>/cve-findings")
def cve_findings(scan_id):
    return _sub_report(scan_id, "cve_findings")


@app.get("/api/scans/<scan_id>/certificates")
def certificates(scan_id):
    return _sub_report(scan_id, "certificate_findings")


# --- Standardised format exports (Tier 1) ---

@app.get("/api/scans/<scan_id>/cyclonedx")
def cyclonedx(scan_id):
    report = _get_or_404(scan_id)
    if report is None:
        return _error("Scan not found.", status=404)
    return jsonify(build_cyclonedx_cbom(report))


@app.get("/api/scans/<scan_id>/report.pdf")
def pdf_report(scan_id):
    report = _get_or_404(scan_id)
    if report is None:
        return _error("Scan not found.", status=404)
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        build_pdf_report(report, tmp.name)
        tmp.seek(0)
        data = open(tmp.name, "rb").read()
    return Response(
        data,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=ecdat_report_{scan_id}.pdf"},
    )


# --- Trend / diff (USP) ---

@app.get("/api/scans/<scan_id>/trend")
def trend(scan_id):
    newer = _get_or_404(scan_id)
    if newer is None:
        return _error("Scan not found.", status=404)
    older = storage.previous_scan(scan_id)
    if older is None:
        return jsonify({"message": "No previous scan to compare against -- this is the first scan on record."})
    return jsonify(diff_reports(older, newer))


@app.get("/api/scans/<older_id>/diff/<newer_id>")
def diff(older_id, newer_id):
    older = _get_or_404(older_id)
    newer = _get_or_404(newer_id)
    if older is None or newer is None:
        return _error("One or both scan IDs not found.", status=404)
    return jsonify(diff_reports(older, newer))


# --- What-if simulator (USP) ---

@app.post("/api/scans/<scan_id>/simulate")
def simulate(scan_id):
    report = _get_or_404(scan_id)
    if report is None:
        return _error("Scan not found.", status=404)
    body = request.get_json(silent=True) or {}
    remediated_ids = body.get("remediated_artefact_ids", [])
    if not isinstance(remediated_ids, list):
        return _error("'remediated_artefact_ids' must be a list of artefact id strings.")
    try:
        result = simulate_remediation(report, remediated_ids)
    except ValueError as exc:
        return _error(str(exc), status=422)
    return jsonify(result)


# --- Manual triage / override ---

@app.post("/api/scans/<scan_id>/triage")
def set_triage(scan_id):
    report = _get_or_404(scan_id)
    if report is None:
        return _error("Scan not found.", status=404)
    body = request.get_json(silent=True) or {}
    artefact_id = body.get("artefact_id")
    valid_ids = {a["id"] for a in report["cbom"]}
    if artefact_id not in valid_ids:
        return _error(f"Unknown artefact_id '{artefact_id}' for this scan.", status=422)
    try:
        override = make_override(
            artefact_id=artefact_id,
            status=body.get("status"),
            justification=body.get("justification"),
            reviewer=body.get("reviewer"),
        )
    except ValueError as exc:
        return _error(str(exc), status=422)
    storage.set_override(scan_id, artefact_id, override)
    return jsonify(override), 201


@app.get("/api/scans/<scan_id>/triage")
def get_triage(scan_id):
    report = _get_or_404(scan_id)
    if report is None:
        return _error("Scan not found.", status=404)
    return jsonify(storage.get_overrides(scan_id))


# --- CI/CD gate template ---

@app.get("/api/scans/<scan_id>/ci-gate.yml")
def ci_gate(scan_id):
    report = _get_or_404(scan_id)
    if report is None:
        return _error("Scan not found.", status=404)
    fail_on_tier = request.args.get("fail_on_tier", "Critical")
    api_base = request.args.get("api_base_url", request.host_url.rstrip("/"))
    yaml_text = generate_github_action(api_base_url=api_base, fail_on_tier=fail_on_tier)
    return Response(yaml_text, mimetype="text/yaml")


# --- Tamper-evident signing ---

@app.get("/api/scans/<scan_id>/signature")
def signature(scan_id):
    report = _get_or_404(scan_id)
    if report is None:
        return _error("Scan not found.", status=404)
    return jsonify(sign_report(report))


@app.post("/api/scans/<scan_id>/verify")
def verify(scan_id):
    report = _get_or_404(scan_id)
    if report is None:
        return _error("Scan not found.", status=404)
    body = request.get_json(silent=True) or {}
    signature_block = body.get("signature")
    if not signature_block:
        return _error("Request body must include a 'signature' object (from GET /signature).")
    valid = verify_report(report, signature_block)
    return jsonify({"valid": valid})


# --- API documentation ---

@app.get("/api/openapi.json")
def openapi_json():
    return jsonify(build_openapi_spec())


@app.get("/api/docs")
def api_docs():
    # Swagger UI bundle loaded from a CDN client-side (needs internet in
    # the browser viewing this page, not on the server). No auth on this
    # route deliberately -- it's documentation, not data.
    html = """<!DOCTYPE html>
<html>
<head>
  <title>ECDAT API Docs</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui.min.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.11.0/swagger-ui-bundle.min.js"></script>
  <script>
    window.onload = () => SwaggerUIBundle({ url: "/api/openapi.json", dom_id: "#swagger-ui" });
  </script>
</body>
</html>"""
    return Response(html, mimetype="text/html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
