"""
Smoke tests for the analysis pipeline and all added modules.
Run with:  python3 tests/test_pipeline.py
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.pipeline import run_pipeline
from app.sample_cbom import SAMPLE_CBOM
from app.aggregation import deduplicate
from app.cyclonedx_export import build_cyclonedx_cbom
from app.trend_analysis import diff_reports
from app.simulator import simulate_remediation
from app.triage import apply_overrides, make_override
from app.ci_cd_template import generate_github_action
from app.report_signing import sign_report, verify_report
from app.regulatory_mapping import map_regulatory_flags
from app.cve_lookup import lookup_all as lookup_cves_all
from app import storage
from app.validation import validate_raw_cbom, ValidationError, MAX_ARTEFACTS_PER_SCAN
from app.rate_limit import check_rate_limit, reset_all as reset_rate_limits
from app.openapi_spec import build_openapi_spec


# ---------------------------------------------------------------- core pipeline

def test_pipeline_runs_end_to_end():
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    assert report["artefact_count"] > 0
    assert "agility_score" in report


def test_rsa_2048_is_flagged_shor_breakable():
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    rsa_cert = next(c for c in report["classifications"] if c["artefact_id"] == "art-001")
    assert rsa_cert["vulnerability_tier"] == "shor_breakable"


def test_already_pqc_artefact_is_marked_safe():
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    pqc_artefact = next(r for r in report["risks"] if r["artefact_id"] == "art-008")
    assert pqc_artefact["risk_tier"] == "Safe"
    assert pqc_artefact["at_risk"] is False


def test_recommendations_generated_for_every_artefact():
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    assert len(report["recommendations"]) == report["artefact_count"]


def test_hndl_exposure_excludes_signature_only_algorithms():
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    hndl_ids = {a["artefact_id"] for a in report["harvest_now_decrypt_later"]["top_exposed_artefacts"]}
    assert "art-007" not in hndl_ids  # DSA signing key -- not a confidentiality mechanism


def test_shorter_crqc_horizon_increases_risk_count():
    report_far = run_pipeline(SAMPLE_CBOM, years_to_crqc=25)
    report_near = run_pipeline(SAMPLE_CBOM, years_to_crqc=5)
    assert report_near["risk_tier_counts"].get("Critical", 0) >= report_far["risk_tier_counts"].get("Critical", 0)


def test_migration_roadmap_has_four_phases():
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    assert len(report["migration_roadmap"]) == 4


def test_blast_radius_computed_for_shared_library():
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    entries = {b["artefact_id"]: b for b in report["dependency_blast_radius"]["highest_blast_radius"]}
    assert "art-005" in entries
    assert entries["art-005"]["blast_radius"] == 4


# ---------------------------------------------------------------- aggregation / dedup

def test_deduplication_merges_repeated_findings():
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    merged = next(a for a in report["cbom"] if a["name"] == "config-secrets-cipher")
    assert merged["occurrence_count"] == 3
    assert len(merged["locations"]) == 3
    assert report["artefact_count"] < len(SAMPLE_CBOM)  # fewer artefacts than raw findings


def test_deduplication_is_order_stable_and_idempotent():
    raw = [
        {"id": "x1", "name": "n", "type": "algorithm", "algorithm": "AES-128", "location": "a", "data_classification": "internal"},
        {"id": "x2", "name": "n", "type": "algorithm", "algorithm": "AES-128", "location": "b", "data_classification": "internal"},
    ]
    merged = deduplicate(raw)
    assert len(merged) == 1
    assert merged[0]["occurrence_count"] == 2
    # running twice on already-deduped input should be a no-op
    merged_again = deduplicate(merged)
    assert len(merged_again) == 1
    assert merged_again[0]["occurrence_count"] == 1  # already one "raw" entry this time


def test_dedup_keeps_most_sensitive_classification():
    raw = [
        {"id": "y1", "name": "n2", "type": "key", "algorithm": "RSA-2048", "location": "a", "data_classification": "internal"},
        {"id": "y2", "name": "n2", "type": "key", "algorithm": "RSA-2048", "location": "b", "data_classification": "PII"},
    ]
    merged = deduplicate(raw)
    assert merged[0]["data_classification"] == "PII"


# ---------------------------------------------------------------- confidence capping

def test_low_confidence_finding_is_capped_below_critical():
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=5)  # aggressive horizon would normally push DES to Critical
    des_risk = next(r for r in report["risks"] if r["artefact_id"] == "art-014")
    assert des_risk["risk_tier"] != "Critical"
    assert des_risk["confidence"] == "low"


# ---------------------------------------------------------------- regulatory mapping

def test_pii_artefact_flagged_for_dpdp():
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    flag = next(f for f in report["regulatory_flags"] if f["artefact_id"] == "art-002")  # PII, internet-facing
    assert "DPDP Act 2023" in flag["frameworks"]


def test_regulatory_reason_discloses_its_not_legal_advice():
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    flag = next(f for f in report["regulatory_flags"] if f["frameworks"])
    assert "not a legal compliance determination" in flag["reason"]


# ---------------------------------------------------------------- CVE lookup

def test_vulnerable_openssl_version_flagged():
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    cves = [c for c in report["cve_findings"] if c["artefact_id"] == "art-005"]
    assert len(cves) > 0
    assert all(c["cve_id"].startswith("CVE-") for c in cves)


def test_no_cve_fabricated_for_artefact_without_library_metadata():
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    cve_ids_covered = {c["artefact_id"] for c in report["cve_findings"]}
    assert "art-001" not in cve_ids_covered  # certificate, not a library w/ version


# ---------------------------------------------------------------- certificate analysis

def test_expired_self_signed_weak_sig_cert_flagged():
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    finding = next(f for f in report["certificate_findings"] if f["artefact_id"] == "art-013")
    joined = " ".join(finding["issues"]).lower()
    assert "expired" in joined
    assert "self-signed" in joined
    assert "weak" in joined


# ---------------------------------------------------------------- CycloneDX export

def test_cyclonedx_export_has_required_top_level_fields():
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    bom = build_cyclonedx_cbom(report)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert len(bom["components"]) == report["artefact_count"]
    assert all(c["type"] == "cryptographic-asset" for c in bom["components"])


def test_cyclonedx_serial_number_is_a_valid_uuid_urn():
    """
    CycloneDX requires serialNumber to be a real RFC 4122 UUID URN --
    a real consumer (e.g. Dependency-Track) validates this and rejects
    a malformed one. Parse it back with the stdlib uuid module to make
    sure it's not just uuid-shaped text.
    """
    import uuid as uuid_module
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    bom = build_cyclonedx_cbom(report)
    serial = bom["serialNumber"]
    assert serial.startswith("urn:uuid:")
    parsed = uuid_module.UUID(serial.replace("urn:uuid:", ""))  # raises ValueError if invalid
    assert str(parsed) == serial.replace("urn:uuid:", "")


def test_cyclonedx_serial_number_is_deterministic_per_scan():
    """Same scan_id should always derive the same serialNumber (useful for re-export/idempotency checks)."""
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    bom1 = build_cyclonedx_cbom(report)
    bom2 = build_cyclonedx_cbom(report)
    assert bom1["serialNumber"] == bom2["serialNumber"]


# ---------------------------------------------------------------- trend analysis

def test_trend_detects_newly_introduced_artefact():
    base_cbom = SAMPLE_CBOM[:5]
    extended_cbom = SAMPLE_CBOM[:6]
    older = run_pipeline(base_cbom, years_to_crqc=12)
    newer = run_pipeline(extended_cbom, years_to_crqc=12)
    result = diff_reports(older, newer)
    assert len(result["newly_introduced_artefacts"]) >= 1


def test_trend_detects_remediation_improvement():
    older = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    remediated_cbom = [dict(a) for a in SAMPLE_CBOM]
    for a in remediated_cbom:
        if a["id"] == "art-001":
            a["algorithm"] = "ML-KEM-768"  # simulate migration
    newer = run_pipeline(remediated_cbom, years_to_crqc=12)
    result = diff_reports(older, newer)
    improved_ids = {i["id"] for i in result["risk_improved"]}
    assert "art-001" in improved_ids


# ---------------------------------------------------------------- what-if simulator

def test_simulator_projects_score_improvement():
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    critical_ids = [r["artefact_id"] for r in report["risks"] if r["risk_tier"] == "Critical"]
    assert critical_ids, "expected at least one critical artefact in the sample data"
    result = simulate_remediation(report, critical_ids)
    assert result["projected_agility_score"] >= result["current_agility_score"]
    assert result["projected_risk_tier_counts"].get("Critical", 0) == 0


def test_simulator_rejects_unknown_artefact_id():
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    try:
        simulate_remediation(report, ["not-a-real-id"])
        assert False, "expected ValueError"
    except ValueError:
        pass


# ---------------------------------------------------------------- triage / override

def test_false_positive_override_downgrades_to_safe():
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    override = make_override("art-014", "false_positive", "Confirmed it's just a comment, not real DES usage.", "reviewer1")
    adjusted = apply_overrides(report["risks"], {"art-014": override})
    entry = next(r for r in adjusted if r["artefact_id"] == "art-014")
    assert entry["risk_tier"] == "Safe"
    assert entry["at_risk"] is False


def test_override_requires_justification():
    try:
        make_override("art-014", "false_positive", "", "reviewer1")
        assert False, "expected ValueError for empty justification"
    except ValueError:
        pass


def test_override_rejects_invalid_status():
    try:
        make_override("art-014", "not_a_real_status", "some reason", "reviewer1")
        assert False, "expected ValueError for invalid status"
    except ValueError:
        pass


# ---------------------------------------------------------------- CI/CD template

def test_ci_gate_yaml_is_valid_and_contains_fail_condition():
    import yaml as pyyaml
    text = generate_github_action(api_base_url="https://example.com", fail_on_tier="Critical")
    parsed = pyyaml.safe_load(text)
    assert "jobs" in parsed
    assert "Critical" in text


# ---------------------------------------------------------------- report signing

def test_report_signature_round_trip_verifies():
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    sig = sign_report(report)
    assert verify_report(report, sig) is True


def test_tampered_report_fails_verification():
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    sig = sign_report(report)
    tampered = dict(report)
    tampered["artefact_count"] = 99999
    assert verify_report(tampered, sig) is False


# ---------------------------------------------------------------- persistent storage

def test_storage_round_trips_a_scan():
    storage.reset_all()
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    storage.save_scan(report)
    reloaded = storage.get_scan(report["scan_id"])
    assert reloaded is not None
    assert reloaded["scan_id"] == report["scan_id"]
    assert reloaded["artefact_count"] == report["artefact_count"]


def test_storage_previous_scan_ordering():
    storage.reset_all()
    older = run_pipeline(SAMPLE_CBOM[:5], years_to_crqc=12)
    storage.save_scan(older)
    newer = run_pipeline(SAMPLE_CBOM[:8], years_to_crqc=12)
    storage.save_scan(newer)
    prev = storage.previous_scan(newer["scan_id"])
    assert prev is not None
    assert prev["scan_id"] == older["scan_id"]
    assert storage.previous_scan(older["scan_id"]) is None  # first scan has no predecessor


def test_storage_overrides_round_trip():
    storage.reset_all()
    report = run_pipeline(SAMPLE_CBOM, years_to_crqc=12)
    storage.save_scan(report)
    override = make_override("art-014", "false_positive", "test justification", "reviewer1")
    storage.set_override(report["scan_id"], "art-014", override)
    overrides = storage.get_overrides(report["scan_id"])
    assert "art-014" in overrides
    assert overrides["art-014"]["status"] == "false_positive"


# ---------------------------------------------------------------- input validation

def test_validation_accepts_the_sample_cbom():
    validate_raw_cbom(SAMPLE_CBOM)  # should not raise


def test_validation_rejects_missing_required_field():
    bad = [{"name": "no-id-here", "type": "algorithm", "algorithm": "AES-128", "location": "x"}]
    try:
        validate_raw_cbom(bad)
        assert False, "expected ValidationError"
    except ValidationError as e:
        assert any(d["field"] == "id" for d in e.details)


def test_validation_rejects_invalid_type_enum():
    bad = [{"id": "a1", "name": "n", "type": "not-a-real-type", "algorithm": "AES-128", "location": "x"}]
    try:
        validate_raw_cbom(bad)
        assert False, "expected ValidationError"
    except ValidationError as e:
        assert any(d["field"] == "type" for d in e.details)


def test_validation_rejects_duplicate_ids():
    item = {"id": "dup-1", "name": "n", "type": "algorithm", "algorithm": "AES-128", "location": "x"}
    bad = [item, dict(item)]
    try:
        validate_raw_cbom(bad)
        assert False, "expected ValidationError"
    except ValidationError as e:
        assert any(d["field"] == "id" and "Duplicate" in d["message"] for d in e.details)


def test_validation_enforces_size_cap():
    template = {"id": "x", "name": "n", "type": "algorithm", "algorithm": "AES-128", "location": "loc"}
    too_many = [dict(template, id=f"x{i}") for i in range(MAX_ARTEFACTS_PER_SCAN + 1)]
    try:
        validate_raw_cbom(too_many)
        assert False, "expected ValidationError"
    except ValidationError as e:
        assert "exceeding" in e.message


def test_validation_rejects_non_list_input():
    try:
        validate_raw_cbom({"not": "a list"})
        assert False, "expected ValidationError"
    except ValidationError:
        pass


def test_validation_rejects_negative_key_length():
    bad = [{"id": "a1", "name": "n", "type": "key", "algorithm": "RSA-2048", "location": "x", "key_length": -5}]
    try:
        validate_raw_cbom(bad)
        assert False, "expected ValidationError"
    except ValidationError as e:
        assert any(d["field"] == "key_length" for d in e.details)


# ---------------------------------------------------------------- rate limiting

def test_rate_limit_allows_up_to_the_limit_then_blocks():
    reset_rate_limits()
    key = "test-key-rate-limit"
    for _ in range(15):
        allowed, retry_after = check_rate_limit(key, bucket="heavy")
        assert allowed is True
    blocked, retry_after = check_rate_limit(key, bucket="heavy")
    assert blocked is False
    assert retry_after is not None and retry_after > 0


def test_rate_limit_buckets_are_independent_per_key():
    reset_rate_limits()
    for _ in range(15):
        assert check_rate_limit("key-a", bucket="heavy")[0] is True
    # a different key should not be affected by key-a's usage
    assert check_rate_limit("key-b", bucket="heavy")[0] is True


# ---------------------------------------------------------------- OpenAPI spec

def test_openapi_spec_is_well_formed():
    spec = build_openapi_spec()
    assert spec["openapi"].startswith("3.0")
    assert "/api/scans" in spec["paths"]
    assert "post" in spec["paths"]["/api/scans"]
    assert "ApiKeyAuth" in spec["components"]["securitySchemes"]


def test_openapi_spec_covers_every_registered_flask_route():
    """
    Every /api/* route in api.py should have a corresponding entry in
    the OpenAPI spec -- catches the case where someone adds a new
    endpoint and forgets to document it.
    """
    from app.api import app as flask_app
    spec = build_openapi_spec()
    documented_paths = set(spec["paths"].keys())

    undocumented = []
    for rule in flask_app.url_map.iter_rules():
        if not rule.rule.startswith("/api/"):
            continue
        if rule.rule in ("/api/openapi.json", "/api/docs", "/api/<path:_any>"):
            continue  # docs routes are intentionally undocumented-in-themselves; the OPTIONS catch-all isn't a real endpoint
        if not rule.methods or ("GET" not in rule.methods and "POST" not in rule.methods):
            continue
        # Flask uses <scan_id>, OpenAPI uses {scan_id} -- normalise for comparison
        normalised = rule.rule
        for arg in rule.arguments:
            normalised = normalised.replace(f"<{arg}>", f"{{{arg}}}")
        if normalised not in documented_paths:
            undocumented.append(normalised)

    assert not undocumented, f"Undocumented routes: {undocumented}"


if __name__ == "__main__":
    tests = [obj for name, obj in list(globals().items()) if name.startswith("test_")]
    passed, failed = 0, 0
    for t in tests:
        try:
            t()
            print(f"PASS: {t.__name__}")
            passed += 1
        except Exception as e:  # noqa: BLE001
            print(f"FAIL: {t.__name__} -- {type(e).__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
