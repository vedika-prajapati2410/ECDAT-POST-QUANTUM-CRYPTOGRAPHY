"""
Pipeline orchestrator: raw CBOM in -> full analysed report out.

This is the single function the API layer (and, eventually, Dev 1's
scanner trigger) calls. Keeping it separate from the Flask routes
means it's trivially testable/callable from a script or notebook too.
"""

import uuid
from datetime import datetime, timezone

from app.models import CryptoArtefact, AssetType
from app.aggregation import deduplicate
from app.classification import classify_all
from app.risk_engine import assess_all, DEFAULT_YEARS_TO_CRQC
from app.recommendations import recommend_all
from app.agility_score import compute_agility_score
from app.migration_roadmap import build_roadmap
from app.harvest_now import compute_hndl_exposure
from app.dependency_graph import build_blast_radius
from app.regulatory_mapping import map_all as map_regulatory_all
from app.cve_lookup import lookup_all as lookup_cves_all
from app.certificate_analysis import analyze_all as analyze_certificates_all


def _to_artefact(d: dict) -> CryptoArtefact:
    d = dict(d)
    d["type"] = AssetType(d["type"])
    known_fields = CryptoArtefact.__dataclass_fields__.keys()
    d = {k: v for k, v in d.items() if k in known_fields}
    return CryptoArtefact(**d)


def run_pipeline(raw_cbom: list, years_to_crqc: float = DEFAULT_YEARS_TO_CRQC, skip_dedup: bool = False) -> dict:
    # 1. Deduplicate raw scanner findings BEFORE anything else sees them.
    deduped = raw_cbom if skip_dedup else deduplicate(raw_cbom)
    artefacts = [_to_artefact(d) for d in deduped]

    # 2. Core pipeline: classify -> risk -> recommend.
    classifications = classify_all(artefacts)
    risks = assess_all(artefacts, classifications, years_to_crqc)
    recommendations = recommend_all(artefacts, classifications, risks)

    # 3. USP analyses.
    agility = compute_agility_score(classifications, risks)
    roadmap = build_roadmap(artefacts, classifications, risks, recommendations)
    hndl = compute_hndl_exposure(artefacts, classifications, years_to_crqc)
    blast_radius = build_blast_radius(artefacts, risks)
    regulatory_flags = map_regulatory_all(artefacts, classifications)
    cve_findings = lookup_cves_all(artefacts)
    cert_findings = analyze_certificates_all(artefacts)

    risk_tier_counts = {}
    for r in risks:
        risk_tier_counts[r.risk_tier.value] = risk_tier_counts.get(r.risk_tier.value, 0) + 1

    dedup_stats = {
        "raw_finding_count": len(raw_cbom),
        "deduplicated_artefact_count": len(artefacts),
        "total_occurrences_merged": sum(a.occurrence_count for a in artefacts),
    }

    low_confidence_count = sum(1 for a in artefacts if a.confidence.value == "low")

    scan_id = str(uuid.uuid4())[:8]
    return {
        "scan_id": scan_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "years_to_crqc_assumption": years_to_crqc,
        "artefact_count": len(artefacts),
        "risk_tier_counts": risk_tier_counts,
        "deduplication_stats": dedup_stats,
        "low_confidence_findings_count": low_confidence_count,
        "cbom": [a.to_dict() for a in artefacts],
        "classifications": [vars(c) | {"vulnerability_tier": c.vulnerability_tier.value} for c in classifications],
        "risks": [vars(r) | {"risk_tier": r.risk_tier.value} for r in risks],
        "recommendations": [vars(r) | {"priority": r.priority.value} for r in recommendations],
        "agility_score": agility,
        "migration_roadmap": roadmap,
        "harvest_now_decrypt_later": hndl,
        "dependency_blast_radius": blast_radius,
        "regulatory_flags": [vars(f) for f in regulatory_flags],
        "cve_findings": [vars(f) for f in cve_findings],
        "certificate_findings": [vars(f) for f in cert_findings],
    }
