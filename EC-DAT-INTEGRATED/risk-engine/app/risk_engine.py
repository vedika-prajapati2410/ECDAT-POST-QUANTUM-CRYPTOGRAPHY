"""
Risk Engine -- Mosca's Theorem
================================
Mosca's inequality: if X + Y > Z, the data/system is at risk.

  X = shelf-life of the data (how long it must stay confidential)
  Y = time required to migrate the system to PQC
  Z = time until a cryptographically-relevant quantum computer (CRQC) exists

We compute this per-artefact using configurable lookup tables (so a
judge/user can tweak assumptions live in the demo), then combine the
margin with the artefact's quantum-vulnerability tier and business
criticality to produce a final risk tier.
"""

from app.models import RiskResult, RiskTier, VulnerabilityTier, CryptoArtefact, ClassificationResult

# --- Configurable assumptions (defaults are conservative, industry-cited) ---

# X: how long data of this classification needs to stay confidential (years)
DATA_SHELF_LIFE_YEARS = {
    "PII": 20,
    "financial": 15,
    "internal": 7,
    "public": 1,
}

# Y: estimated engineering effort to migrate an artefact of this type (years)
MIGRATION_TIME_YEARS = {
    "certificate": 0.5,
    "key": 0.5,
    "protocol": 1.5,
    "library": 1.0,
    "algorithm": 1.0,
}

# Z: time until a cryptographically-relevant quantum computer (CRQC) is
# expected to exist. This is genuinely uncertain and disputed -- we do
# NOT present a single number as settled fact. Two independent public
# anchors are commonly cited when organisations pick a planning horizon:
#   1. NSA's CNSA 2.0 suite sets phased mandatory-use-by deadlines for
#      quantum-resistant algorithms across National Security Systems,
#      running through 2033 -- i.e. the US government's own migration
#      deadline, not a CRQC-arrival prediction.
#   2. Industry expert-elicitation surveys (e.g. the Global Risk
#      Institute's annual Quantum Threat Timeline report) have
#      historically clustered median CRQC-arrival estimates in the
#      early-to-mid 2030s, with wide uncertainty bands either side.
# We default Z to 12 years (roughly the CNSA 2.0 2033 deadline from a
# 2026 baseline) purely as a *planning* assumption, and expose it as a
# request parameter (`years_to_crqc`) so the frontend can offer a
# slider for scenario analysis -- this is a live demo strength, not a
# hidden constant. Always disclose this assumption alongside any
# report; do not present Z as a verified fact.
DEFAULT_YEARS_TO_CRQC = 12.0

# Artefacts detected with low scanner confidence are capped below
# Critical even if the raw Mosca math says otherwise -- an unverified
# finding shouldn't trigger the same alarm as a confirmed one. This
# closes the "the demo cried wolf on a false positive" failure mode.
CONFIDENCE_RISK_CAP = {
    "low": RiskTier.MEDIUM,
    "medium": RiskTier.HIGH,
    "high": None,  # no cap
}


def _business_criticality(artefact: CryptoArtefact) -> str:
    """
    Heuristic criticality tagging: combines explicit internet-facing flag
    and data classification. In production this would also merge in
    manual overrides from the org (asset owner tags a system as
    'crown jewel', etc.) -- we expose that as data_classification today.
    """
    if artefact.internet_facing and artefact.data_classification in ("PII", "financial"):
        return "Crown Jewel"
    if artefact.internet_facing or artefact.data_classification in ("PII", "financial"):
        return "Important"
    return "Standard"


def assess_risk(
    artefact: CryptoArtefact,
    classification: ClassificationResult,
    years_to_crqc: float = DEFAULT_YEARS_TO_CRQC,
) -> RiskResult:
    x = DATA_SHELF_LIFE_YEARS.get(artefact.data_classification, 5)
    y = MIGRATION_TIME_YEARS.get(
        artefact.type.value if hasattr(artefact.type, "value") else artefact.type, 1.0
    )
    z = years_to_crqc

    margin = z - (x + y)          # negative => at risk (Mosca's inequality triggers)
    at_risk = margin < 0

    criticality = _business_criticality(artefact)

    # Already quantum-safe artefacts are never "at risk" regardless of margin.
    if classification.vulnerability_tier == VulnerabilityTier.QUANTUM_SAFE:
        tier = RiskTier.SAFE
        at_risk = False
        capped = False
    else:
        tier = _risk_tier(margin, classification.vulnerability_tier, criticality)
        confidence_value = artefact.confidence.value if hasattr(artefact.confidence, "value") else str(artefact.confidence)
        cap = CONFIDENCE_RISK_CAP.get(confidence_value)
        capped = False
        if cap is not None and _TIER_SEVERITY[tier] > _TIER_SEVERITY[cap]:
            tier = cap
            capped = True

    return RiskResult(
        artefact_id=artefact.id,
        x_data_shelf_life_years=x,
        y_migration_time_years=y,
        z_years_to_crqc=z,
        exposure_margin_years=round(margin, 2),
        at_risk=at_risk,
        risk_tier=tier,
        business_criticality=criticality,
        confidence=artefact.confidence.value if hasattr(artefact.confidence, "value") else str(artefact.confidence),
        confidence_capped=capped,
    )


_TIER_SEVERITY = {
    RiskTier.SAFE: 0,
    RiskTier.LOW: 1,
    RiskTier.MEDIUM: 2,
    RiskTier.HIGH: 3,
    RiskTier.CRITICAL: 4,
}


def _risk_tier(margin: float, vuln_tier: VulnerabilityTier, criticality: str) -> RiskTier:
    """
    Combine Mosca margin + how badly the algorithm itself is broken +
    how important the system is, into one human-readable tier.

    Shor-breakable algorithms are treated as strictly worse than
    Grover-weakened ones at the same margin, since a CRQC breaks them
    outright rather than merely halving effective strength.
    """
    severity = 0

    # margin-based severity
    if margin < -5:
        severity += 3
    elif margin < 0:
        severity += 2
    elif margin < 3:
        severity += 1

    # algorithm-break severity
    if vuln_tier == VulnerabilityTier.SHOR_BREAKABLE:
        severity += 2
    elif vuln_tier == VulnerabilityTier.GROVER_WEAKENED:
        severity += 1

    # criticality weighting
    if criticality == "Crown Jewel":
        severity += 2
    elif criticality == "Important":
        severity += 1

    if severity >= 6:
        return RiskTier.CRITICAL
    if severity >= 4:
        return RiskTier.HIGH
    if severity >= 2:
        return RiskTier.MEDIUM
    return RiskTier.LOW


def assess_all(artefacts, classifications, years_to_crqc: float = DEFAULT_YEARS_TO_CRQC):
    class_by_id = {c.artefact_id: c for c in classifications}
    return [assess_risk(a, class_by_id[a.id], years_to_crqc) for a in artefacts]
