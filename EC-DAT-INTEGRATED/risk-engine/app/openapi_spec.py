"""
OpenAPI 3.0 specification for the ECDAT API.

Built as a plain Python dict (not loaded from a separate YAML file) so
there's exactly one source of truth that can't silently drift out of
sync with app/api.py -- update a route, update its entry here in the
same diff. Served as JSON at GET /api/openapi.json, and as an
interactive Swagger UI page at GET /api/docs (loads the Swagger UI
bundle from a CDN client-side -- needs internet in the browser
viewing it, not on the server).
"""

_SCAN_ID_PARAM = {
    "name": "scan_id", "in": "path", "required": True,
    "schema": {"type": "string"}, "description": "Scan ID returned by POST /api/scans or /api/scans/sample.",
}

_API_KEY_SECURITY = [{"ApiKeyAuth": []}]

_ERROR_RESPONSE = {
    "description": "Error",
    "content": {"application/json": {"schema": {
        "type": "object",
        "properties": {
            "error": {"type": "string"},
            "details": {"type": "array", "items": {"type": "object"}},
        },
    }}},
}

_GENERIC_JSON_RESPONSE = {
    "description": "Success",
    "content": {"application/json": {"schema": {"type": "object"}}},
}


def _sub_report_path(sub_path, summary, description=""):
    return {
        "get": {
            "summary": summary,
            "description": description,
            "security": _API_KEY_SECURITY,
            "parameters": [_SCAN_ID_PARAM],
            "responses": {"200": _GENERIC_JSON_RESPONSE, "404": _ERROR_RESPONSE},
        }
    }


def build_openapi_spec() -> dict:
    paths = {
        "/api/health": {
            "get": {
                "summary": "Liveness check",
                "security": [],
                "responses": {"200": _GENERIC_JSON_RESPONSE},
            }
        },
        "/api/scans": {
            "post": {
                "summary": "Run a new scan against submitted CBOM findings",
                "description": (
                    "Runs the full pipeline: validation -> deduplication -> classification -> "
                    "Mosca risk scoring -> recommendations -> agility score -> roadmap -> HNDL "
                    "exposure -> blast radius -> regulatory mapping -> CVE lookup -> cert analysis. "
                    "Rate-limited to the 'heavy' bucket (see X-RateLimit-* response headers)."
                ),
                "security": _API_KEY_SECURITY,
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {
                        "type": "object",
                        "required": ["cbom"],
                        "properties": {
                            "cbom": {
                                "type": "array",
                                "description": "Raw artefact findings. See CryptoArtefact schema in app/models.py.",
                                "items": {"type": "object"},
                                "maxItems": 5000,
                            },
                            "years_to_crqc": {"type": "number", "default": 12.0, "description": "Z in Mosca's theorem: planning horizon in years."},
                            "skip_dedup": {"type": "boolean", "default": False},
                        },
                    }}},
                },
                "responses": {
                    "201": {"description": "Scan created", "content": {"application/json": {"schema": {"type": "object"}}}},
                    "422": _ERROR_RESPONSE,
                    "429": {"description": "Rate limit exceeded", "content": {"application/json": {"schema": {"type": "object"}}}},
                },
            },
            "get": {
                "summary": "List scan history (most recent first)",
                "security": _API_KEY_SECURITY,
                "responses": {"200": _GENERIC_JSON_RESPONSE},
            },
        },
        "/api/scans/sample": {
            "post": {
                "summary": "Run a scan against the built-in sample CBOM (for demoing before the scanner is wired up)",
                "security": _API_KEY_SECURITY,
                "requestBody": {"required": False, "content": {"application/json": {"schema": {
                    "type": "object", "properties": {"years_to_crqc": {"type": "number", "default": 12.0}},
                }}}},
                "responses": {"201": _GENERIC_JSON_RESPONSE},
            }
        },
        "/api/scans/{scan_id}": {
            "get": {
                "summary": "Full report (all sections combined, with any triage overrides applied)",
                "security": _API_KEY_SECURITY,
                "parameters": [_SCAN_ID_PARAM],
                "responses": {"200": _GENERIC_JSON_RESPONSE, "404": _ERROR_RESPONSE},
            }
        },
        "/api/scans/{scan_id}/cbom": _sub_report_path("cbom", "Normalised, deduplicated artefact inventory"),
        "/api/scans/{scan_id}/risk": _sub_report_path("risk", "Per-artefact Mosca risk assessment (with triage overrides applied)"),
        "/api/scans/{scan_id}/recommendations": _sub_report_path("recommendations", "PQC/hybrid replacement + tradeoffs per artefact"),
        "/api/scans/{scan_id}/agility-score": _sub_report_path("agility-score", "Crypto-Agility Score (0-100) + maturity level"),
        "/api/scans/{scan_id}/roadmap": _sub_report_path("roadmap", "Phased migration roadmap"),
        "/api/scans/{scan_id}/hndl": _sub_report_path("hndl", "Harvest-now-decrypt-later exposure estimate"),
        "/api/scans/{scan_id}/blast-radius": _sub_report_path("blast-radius", "Dependency blast-radius graph"),
        "/api/scans/{scan_id}/regulatory": _sub_report_path("regulatory", "Indian regulatory/compliance triage flags (not legal advice)"),
        "/api/scans/{scan_id}/cve-findings": _sub_report_path("cve-findings", "CVE cross-reference findings for library artefacts"),
        "/api/scans/{scan_id}/certificates": _sub_report_path("certificates", "Certificate deep-analysis findings (expiry, self-signed, weak sig hash)"),
        "/api/scans/{scan_id}/cyclonedx": {
            "get": {
                "summary": "CycloneDX 1.6 CBOM export",
                "security": _API_KEY_SECURITY,
                "parameters": [_SCAN_ID_PARAM],
                "responses": {"200": {"description": "CycloneDX BOM", "content": {"application/json": {"schema": {"type": "object"}}}}, "404": _ERROR_RESPONSE},
            }
        },
        "/api/scans/{scan_id}/report.pdf": {
            "get": {
                "summary": "Human-readable PDF report",
                "security": _API_KEY_SECURITY,
                "parameters": [_SCAN_ID_PARAM],
                "responses": {"200": {"description": "PDF file", "content": {"application/pdf": {"schema": {"type": "string", "format": "binary"}}}}, "404": _ERROR_RESPONSE},
            }
        },
        "/api/scans/{scan_id}/trend": _sub_report_path("trend", "Diff against the immediately previous scan (new/resolved artefacts, score delta)"),
        "/api/scans/{older_id}/diff/{newer_id}": {
            "get": {
                "summary": "Diff between two specific scans",
                "security": _API_KEY_SECURITY,
                "parameters": [
                    {"name": "older_id", "in": "path", "required": True, "schema": {"type": "string"}},
                    {"name": "newer_id", "in": "path", "required": True, "schema": {"type": "string"}},
                ],
                "responses": {"200": _GENERIC_JSON_RESPONSE, "404": _ERROR_RESPONSE},
            }
        },
        "/api/scans/{scan_id}/simulate": {
            "post": {
                "summary": "What-if remediation simulator",
                "description": "Projects the Agility Score and risk-tier counts if the given artefact IDs were remediated, without persisting anything.",
                "security": _API_KEY_SECURITY,
                "parameters": [_SCAN_ID_PARAM],
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object",
                    "properties": {"remediated_artefact_ids": {"type": "array", "items": {"type": "string"}}},
                }}}},
                "responses": {"200": _GENERIC_JSON_RESPONSE, "404": _ERROR_RESPONSE, "422": _ERROR_RESPONSE},
            }
        },
        "/api/scans/{scan_id}/triage": {
            "post": {
                "summary": "Set a manual triage override for one artefact",
                "security": _API_KEY_SECURITY,
                "parameters": [_SCAN_ID_PARAM],
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object",
                    "required": ["artefact_id", "status", "justification", "reviewer"],
                    "properties": {
                        "artefact_id": {"type": "string"},
                        "status": {"type": "string", "enum": ["accepted_risk", "false_positive", "confirmed"]},
                        "justification": {"type": "string"},
                        "reviewer": {"type": "string"},
                    },
                }}}},
                "responses": {"201": _GENERIC_JSON_RESPONSE, "404": _ERROR_RESPONSE, "422": _ERROR_RESPONSE},
            },
            "get": {
                "summary": "List current triage overrides for a scan",
                "security": _API_KEY_SECURITY,
                "parameters": [_SCAN_ID_PARAM],
                "responses": {"200": _GENERIC_JSON_RESPONSE, "404": _ERROR_RESPONSE},
            },
        },
        "/api/scans/{scan_id}/ci-gate.yml": {
            "get": {
                "summary": "Generated GitHub Actions workflow that fails a build on new non-PQC crypto",
                "security": _API_KEY_SECURITY,
                "parameters": [
                    _SCAN_ID_PARAM,
                    {"name": "fail_on_tier", "in": "query", "schema": {"type": "string", "default": "Critical"}},
                    {"name": "api_base_url", "in": "query", "schema": {"type": "string"}},
                ],
                "responses": {"200": {"description": "YAML workflow", "content": {"text/yaml": {"schema": {"type": "string"}}}}, "404": _ERROR_RESPONSE},
            }
        },
        "/api/scans/{scan_id}/signature": {
            "get": {
                "summary": "Tamper-evident signature for the report (Ed25519 today; ML-DSA-ready interface)",
                "security": _API_KEY_SECURITY,
                "parameters": [_SCAN_ID_PARAM],
                "responses": {"200": _GENERIC_JSON_RESPONSE, "404": _ERROR_RESPONSE},
            }
        },
        "/api/scans/{scan_id}/verify": {
            "post": {
                "summary": "Verify a report + signature pair",
                "security": _API_KEY_SECURITY,
                "parameters": [_SCAN_ID_PARAM],
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object", "required": ["signature"], "properties": {"signature": {"type": "object"}},
                }}}},
                "responses": {"200": {"description": "{'valid': true|false}", "content": {"application/json": {"schema": {"type": "object"}}}}, "404": _ERROR_RESPONSE},
            }
        },
    }

    return {
        "openapi": "3.0.3",
        "info": {
            "title": "ECDAT -- Enterprise Cryptographic Discovery & Analysis Tool API",
            "version": "1.0.0",
            "description": (
                "Backend for SIH Problem Statement 26164. Takes a CBOM (Cryptographic Bill of "
                "Materials) and returns Mosca-theorem risk scoring, PQC recommendations, and "
                "the Crypto-Agility Score, migration roadmap, harvest-now-decrypt-later exposure, "
                "and dependency blast-radius analyses.\n\n"
                "Assumption disclosure: `years_to_crqc` is a configurable planning assumption, "
                "not a verified prediction. Regulatory flags are automated triage suggestions, "
                "not legal advice. See the project README for full disclosures."
            ),
        },
        "servers": [{"url": "/", "description": "Current host"}],
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
            }
        },
        "paths": paths,
    }
