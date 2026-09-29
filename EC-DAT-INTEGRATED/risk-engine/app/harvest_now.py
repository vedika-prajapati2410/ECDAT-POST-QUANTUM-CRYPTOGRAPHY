"""
USP #3: "Harvest Now, Decrypt Later" (HNDL) Exposure Estimate
=================================================================
This is designed to be the single best "wow" moment in the demo: it
turns the abstract X+Y>Z inequality into a concrete, scary number --
how much data being encrypted *today* will still be sensitive by the
time a quantum computer can retroactively decrypt it.

Logic: an artefact is HNDL-exposed if it protects data-in-transit or
data-at-rest confidentiality (key exchange / encryption, not just
signatures -- signing a message doesn't let an attacker "harvest" it
for later decryption) AND its data shelf-life (X) extends beyond the
estimated arrival of a CRQC (Z). That data can be intercepted/stored
today and read the moment a CRQC exists.
"""

from app.models import AssetType, VulnerabilityTier
from app.risk_engine import DATA_SHELF_LIFE_YEARS

# Asset types/algorithm roles that actually protect *confidentiality*
# (as opposed to integrity/authenticity, which HNDL doesn't apply to).
CONFIDENTIALITY_RELEVANT_TYPES = {AssetType.KEY, AssetType.CERTIFICATE, AssetType.PROTOCOL, AssetType.ALGORITHM}
SIGNATURE_ONLY_FAMILIES = {"ML-DSA", "SLH-DSA", "SPHINCS+", "FALCON", "DSA", "ECDSA"}


def compute_hndl_exposure(artefacts, classifications, years_to_crqc: float):
    class_by_id = {c.artefact_id: c for c in classifications}
    exposed = []
    total_exposed_gb = 0.0

    for artefact in artefacts:
        classification = class_by_id[artefact.id]

        if classification.algorithm_family in SIGNATURE_ONLY_FAMILIES:
            continue  # signatures don't protect confidentiality -- not HNDL-relevant
        if classification.vulnerability_tier == VulnerabilityTier.QUANTUM_SAFE:
            continue  # already safe from harvesting attacks

        x = DATA_SHELF_LIFE_YEARS.get(artefact.data_classification, 5)
        if x <= years_to_crqc:
            continue  # data will be worthless/expired before CRQC arrives -- not exposed

        exposure_years_overlap = round(x - years_to_crqc, 1)
        exposed.append({
            "artefact_id": artefact.id,
            "name": artefact.name,
            "location": artefact.location,
            "algorithm": artefact.algorithm,
            "data_classification": artefact.data_classification,
            "data_volume_gb": artefact.data_volume_gb,
            "years_data_remains_sensitive_past_crqc": exposure_years_overlap,
        })
        total_exposed_gb += artefact.data_volume_gb

    exposed.sort(key=lambda e: e["data_volume_gb"], reverse=True)

    return {
        "years_to_crqc_assumption": years_to_crqc,
        "total_exposed_gb": round(total_exposed_gb, 1),
        "exposed_artefact_count": len(exposed),
        "headline": (
            f"{round(total_exposed_gb, 1)} GB of data being encrypted today is harvestable now "
            f"and would be readable within {years_to_crqc:.0f} years, while still being sensitive."
            if total_exposed_gb > 0
            else "No data currently at risk of harvest-now-decrypt-later exposure under current assumptions."
        ),
        "top_exposed_artefacts": exposed[:10],
    }
