"""
USP #2: Phased Migration Roadmap
===================================
Instead of dumping a flat list of flagged artefacts, group them into
an actionable, time-boxed roadmap a decision-maker can hand to
engineering. This is the deliverable most competing tools skip.
"""

from app.models import RiskTier

PHASES = [
    ("Phase 1 (0-6 months)", {RiskTier.CRITICAL}),
    ("Phase 2 (6-18 months)", {RiskTier.HIGH}),
    ("Phase 3 (18-36 months)", {RiskTier.MEDIUM}),
    ("Phase 4 (36+ months / monitor)", {RiskTier.LOW}),
]


def build_roadmap(artefacts, classifications, risks, recommendations):
    art_by_id = {a.id: a for a in artefacts}
    class_by_id = {c.artefact_id: c for c in classifications}
    rec_by_id = {r.artefact_id: r for r in recommendations}

    roadmap = []
    for phase_label, tiers in PHASES:
        items = []
        for risk in risks:
            if risk.risk_tier not in tiers:
                continue
            artefact = art_by_id[risk.artefact_id]
            rec = rec_by_id[risk.artefact_id]
            items.append({
                "artefact_id": artefact.id,
                "name": artefact.name,
                "location": artefact.location,
                "current_algorithm": artefact.algorithm,
                "recommended_algorithm": rec.recommended_algorithm,
                "business_criticality": risk.business_criticality,
                "exposure_margin_years": risk.exposure_margin_years,
            })
        # within a phase, surface Crown Jewel / most negative margin first
        items.sort(key=lambda i: (i["business_criticality"] != "Crown Jewel", i["exposure_margin_years"]))
        roadmap.append({
            "phase": phase_label,
            "artefact_count": len(items),
            "items": items,
        })

    return roadmap
