"""
What-If Remediation Simulator
================================
Live-demo strength: let a user select artefacts to "mark as migrated"
and instantly see the projected Agility Score / risk-tier counts
BEFORE doing the actual engineering work. Cheap to build because it's
just re-running the scoring functions on a modified artefact list --
no new scanning logic needed.
"""

from app.models import RiskTier, VulnerabilityTier
from app.agility_score import compute_agility_score


class _SimClassification:
    def __init__(self, artefact_id, vulnerability_tier):
        self.artefact_id = artefact_id
        self.vulnerability_tier = vulnerability_tier


class _SimRisk:
    def __init__(self, artefact_id, risk_tier, business_criticality, exposure_margin_years):
        self.artefact_id = artefact_id
        self.risk_tier = risk_tier
        self.business_criticality = business_criticality
        self.exposure_margin_years = exposure_margin_years


def simulate_remediation(report: dict, remediated_artefact_ids: list) -> dict:
    """
    Returns a projected agility_score and risk_tier_counts as if every
    artefact in `remediated_artefact_ids` had been migrated to a
    quantum-safe algorithm (risk_tier -> Safe, vulnerability_tier ->
    quantum_safe), holding everything else constant.
    """
    remediated_set = set(remediated_artefact_ids)
    all_ids = {a["id"] for a in report["cbom"]}
    unknown_ids = remediated_set - all_ids
    if unknown_ids:
        raise ValueError(f"Unknown artefact id(s) in remediated_artefact_ids: {sorted(unknown_ids)}")

    sim_classifications = []
    for c in report["classifications"]:
        tier = VulnerabilityTier.QUANTUM_SAFE if c["artefact_id"] in remediated_set else VulnerabilityTier(c["vulnerability_tier"])
        sim_classifications.append(_SimClassification(c["artefact_id"], tier))

    sim_risks = []
    projected_counts = {}
    for r in report["risks"]:
        tier = RiskTier.SAFE if r["artefact_id"] in remediated_set else RiskTier(r["risk_tier"])
        # Margin itself is a property of X/Y/Z, not of the algorithm choice, so we
        # carry the originally-computed margin forward unchanged -- only the tier
        # (and thus the agility score's readiness/distribution components) reflects
        # the hypothetical remediation.
        sim_risks.append(_SimRisk(r["artefact_id"], tier, r["business_criticality"], r["exposure_margin_years"]))
        projected_counts[tier.value] = projected_counts.get(tier.value, 0) + 1

    projected_agility = compute_agility_score(sim_classifications, sim_risks)

    current_score = report["agility_score"]["score"]
    return {
        "remediated_artefact_ids": sorted(remediated_set),
        "current_agility_score": current_score,
        "projected_agility_score": projected_agility["score"],
        "score_improvement": round(projected_agility["score"] - current_score, 1),
        "current_risk_tier_counts": report["risk_tier_counts"],
        "projected_risk_tier_counts": projected_counts,
        "projected_maturity_level": projected_agility["maturity_level_name"],
    }
