"""
Regulatory / Compliance Mapping
==================================
This problem statement is sponsored by NTRO (National Technical
Research Organisation) -- a national-security-adjacent body. Generic
NIST/CNSA framing is table stakes; mapping findings to the Indian
regulatory frameworks that actually govern the affected data is the
differentiator most competing teams will skip.

IMPORTANT HONESTY NOTE: this module flags which frameworks are
*likely relevant* based on data classification and exposure, as a
triage aid for a compliance/legal reviewer -- it is NOT a legal
determination of compliance or non-compliance, and says so in every
output. Do not present this as legal advice.
"""

from app.models import RegulatoryFlag

FRAMEWORK_NOTES = {
    "DPDP Act 2023": (
        "Digital Personal Data Protection Act, 2023 -- governs processing of "
        "personal data of Indian residents; mandates 'reasonable security "
        "safeguards' for personal data, which regulators have interpreted to "
        "include encryption at rest and in transit."
    ),
    "RBI Cybersecurity Framework": (
        "RBI's Cyber Security Framework for banks/NBFCs/payment system "
        "operators -- mandates encryption and key-management controls for "
        "financial data and payment systems."
    ),
    "CERT-In Directions 2022": (
        "CERT-In's April 2022 directions require regulated entities to "
        "maintain ICT system logs and report security incidents; weak "
        "cryptography protecting those logs/systems is a relevant control gap."
    ),
    "SEBI Cybersecurity Framework": (
        "SEBI's Cybersecurity and Cyber Resilience Framework (CSCRF) for "
        "market infrastructure institutions and intermediaries -- mandates "
        "encryption for sensitive financial and client data."
    ),
    "NCIIPC Guidelines": (
        "Applicable where the system qualifies as Critical Information "
        "Infrastructure -- NCIIPC guidance expects strong, current "
        "cryptographic controls and proactive obsolescence management."
    ),
}


def map_regulatory_flags(artefact, classification) -> RegulatoryFlag:
    frameworks = []
    reasons = []

    if artefact.data_classification == "PII":
        frameworks.append("DPDP Act 2023")
        reasons.append("processes/protects personal data of Indian residents")

    if artefact.data_classification == "financial":
        frameworks.append("RBI Cybersecurity Framework")
        frameworks.append("SEBI Cybersecurity Framework")
        reasons.append("protects financial/payment data")

    if artefact.internet_facing:
        frameworks.append("CERT-In Directions 2022")
        reasons.append("internet-facing system in scope for CERT-In logging/incident directions")

    if artefact.internet_facing and artefact.data_classification in ("PII", "financial"):
        frameworks.append("NCIIPC Guidelines")
        reasons.append("potentially qualifies as sensitive/critical infrastructure exposure")

    # De-dup while preserving order
    seen = set()
    frameworks = [f for f in frameworks if not (f in seen or seen.add(f))]

    if not frameworks:
        reason = "No specific Indian regulatory framework auto-matched based on current classification tags."
    else:
        reason = (
            "Flagged for review under: " + "; ".join(reasons) +
            ". This is an automated triage suggestion, not a legal compliance determination -- "
            "route to a compliance/legal reviewer for confirmation."
        )

    return RegulatoryFlag(
        artefact_id=artefact.id,
        frameworks=frameworks,
        reason=reason,
    )


def map_all(artefacts, classifications):
    class_by_id = {c.artefact_id: c for c in classifications}
    return [map_regulatory_flags(a, class_by_id[a.id]) for a in artefacts]


def framework_glossary():
    """Reference glossary for the frontend to render as tooltips."""
    return FRAMEWORK_NOTES
