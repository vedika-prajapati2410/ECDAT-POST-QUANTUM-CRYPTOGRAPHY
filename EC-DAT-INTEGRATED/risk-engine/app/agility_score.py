"""
USP #1: Crypto-Agility Score
==============================
A single 0-100 composite metric summarising how ready the organisation
is for the PQC transition. Almost no CBOM tools compute an aggregate
readiness number -- this is the "one number for the exec slide" that
makes the demo memorable and gives judges an immediate takeaway.

Score = weighted blend of:
  1. % of artefacts already quantum-safe                (readiness)
  2. Average Mosca exposure margin, normalised            (urgency buffer)
  3. Inverse of criticality-weighted risk concentration   (how risk is distributed)
"""

from app.models import RiskTier, VulnerabilityTier

RISK_TIER_WEIGHT = {
    RiskTier.CRITICAL: 4,
    RiskTier.HIGH: 3,
    RiskTier.MEDIUM: 2,
    RiskTier.LOW: 1,
    RiskTier.SAFE: 0,
}

CRITICALITY_WEIGHT = {
    "Crown Jewel": 3,
    "Important": 2,
    "Standard": 1,
}

# CMMI-style maturity levels so a non-technical evaluator can parse the
# score in 2 seconds without needing to interpret a raw number.
MATURITY_LEVELS = [
    (0,  "Level 0 -- Unaware", "No meaningful quantum-readiness posture; crypto inventory largely unknown."),
    (30, "Level 1 -- Initial", "Some visibility into crypto usage, but migration largely unplanned and reactive."),
    (50, "Level 2 -- Developing", "Inventory exists; risk assessment underway but migration not yet systematic."),
    (70, "Level 3 -- Defined", "Documented, risk-prioritised migration plan in progress across critical systems."),
    (85, "Level 4 -- Managed", "Migration actively tracked with metrics; most high-risk systems remediated."),
    (95, "Level 5 -- Optimised", "Quantum-safe by default; continuous monitoring and rapid response to new findings."),
]


def _maturity_level(score: float):
    level = MATURITY_LEVELS[0]
    for threshold, name, desc in MATURITY_LEVELS:
        if score >= threshold:
            level = (threshold, name, desc)
    return {"maturity_level_name": level[1], "maturity_level_description": level[2]}


def compute_agility_score(classifications, risks) -> dict:
    n = len(risks)
    if n == 0:
        return {
            "score": 100,
            "grade": "A",
            "maturity_level_name": "Level 5 -- Optimised",
            "maturity_level_description": "No artefacts scanned yet.",
            "summary": "No artefacts scanned yet.",
            "components": {},
        }

    # 1. Readiness: fraction already quantum-safe
    safe_count = sum(1 for c in classifications if c.vulnerability_tier == VulnerabilityTier.QUANTUM_SAFE)
    readiness_pct = safe_count / n

    # 2. Urgency buffer: average exposure margin, clipped and normalised to [0,1]
    #    margin of +10 years or more => full buffer credit; -10 or worse => none
    margins = [r.exposure_margin_years for r in risks]
    avg_margin = sum(margins) / n
    urgency_buffer = max(0.0, min(1.0, (avg_margin + 10) / 20))

    # 3. Risk concentration: criticality-weighted risk score, inverted
    weighted_risk = sum(
        RISK_TIER_WEIGHT[r.risk_tier] * CRITICALITY_WEIGHT.get(r.business_criticality, 1)
        for r in risks
    )
    max_possible = n * RISK_TIER_WEIGHT[RiskTier.CRITICAL] * CRITICALITY_WEIGHT["Crown Jewel"]
    concentration_penalty = weighted_risk / max_possible if max_possible else 0
    distribution_score = 1.0 - concentration_penalty

    # Weighted blend -> 0-100
    raw = (0.45 * readiness_pct) + (0.25 * urgency_buffer) + (0.30 * distribution_score)
    score = round(raw * 100, 1)

    grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F"
    maturity = _maturity_level(score)

    return {
        "score": score,
        "grade": grade,
        "maturity_level_name": maturity["maturity_level_name"],
        "maturity_level_description": maturity["maturity_level_description"],
        "summary": _summary_for(score, safe_count, n),
        "components": {
            "readiness_pct": round(readiness_pct * 100, 1),
            "urgency_buffer_pct": round(urgency_buffer * 100, 1),
            "risk_distribution_pct": round(distribution_score * 100, 1),
            "quantum_safe_artefacts": safe_count,
            "total_artefacts": n,
        },
    }


def _summary_for(score, safe_count, total):
    if score >= 85:
        return f"Strong PQC posture -- {safe_count}/{total} artefacts already quantum-safe, low concentrated risk."
    if score >= 70:
        return f"Good progress, but action needed -- {safe_count}/{total} artefacts migrated so far."
    if score >= 50:
        return "Moderate exposure. Several critical systems still rely on Shor-breakable algorithms."
    if score >= 30:
        return "High exposure. Migration should begin immediately on Crown Jewel systems."
    return "Critical exposure. Organisation is largely unprepared for the PQC transition."
