"""
Recommendation Engine
=======================
Maps each vulnerable algorithm family to a NIST-standardised PQC or
hybrid replacement, with cost/latency/maturity tradeoff notes -- the
problem statement explicitly asks for recommendations "based on risk
profile, latency, cost, etc." Most competing tools stop at "use
Kyber"; we attach the tradeoffs so the output is decision-ready.
"""

from app.models import Recommendation, RiskTier, VulnerabilityTier, ClassificationResult, RiskResult, CryptoArtefact

# family -> (recommended replacement, rationale, latency_overhead_pct,
#            size_increase, library_maturity)
REPLACEMENT_MAP = {
    "RSA": (
        "ML-KEM-768 (key exchange) + ML-DSA-65 (signatures), or hybrid X25519+ML-KEM-768 during transition",
        "RSA is broken outright by Shor's algorithm; ML-KEM/ML-DSA are the NIST FIPS 203/204 standards.",
        15.0,
        "Keys/ciphertexts ~5-10x larger than RSA-2048",
        "Production-ready (liboqs, OpenSSL 3.2+, BoringSSL)",
    ),
    "DSA": (
        "ML-DSA-65 (Dilithium)",
        "DSA relies on discrete-log hardness, broken by Shor's algorithm.",
        10.0,
        "Signatures ~2.5x larger than DSA-2048",
        "Production-ready (liboqs)",
    ),
    "ECDSA": (
        "ML-DSA-65, or hybrid ECDSA+ML-DSA during transition",
        "Elliptic-curve signatures are broken by Shor's algorithm despite small classical key sizes.",
        8.0,
        "Signatures larger than ECDSA (~2.4KB vs 64B) but still practical for TLS",
        "Production-ready (liboqs, OpenSSL 3.2+)",
    ),
    "ECDH": (
        "ML-KEM-768, or hybrid X25519+ML-KEM-768",
        "Elliptic-curve Diffie-Hellman key exchange is broken by Shor's algorithm.",
        12.0,
        "Ciphertext ~1KB vs ~32B for X25519",
        "Production-ready; hybrid mode already in TLS 1.3 drafts",
    ),
    "DH": (
        "ML-KEM-768, or hybrid finite-field-DH+ML-KEM-768",
        "Classic Diffie-Hellman is broken by Shor's algorithm.",
        12.0,
        "Ciphertext significantly larger than classic DH",
        "Production-ready",
    ),
    "3DES": (
        "AES-256-GCM",
        "3DES is legacy and Grover-weakened; also deprecated for performance/security reasons independent of quantum risk.",
        -20.0,  # actually faster
        "No meaningful size change",
        "Universally supported",
    ),
    "DES": (
        "AES-256-GCM",
        "DES is fully deprecated and Grover-weakened; replace regardless of quantum timeline.",
        -30.0,
        "No meaningful size change",
        "Universally supported",
    ),
    "AES": (
        "AES-256 (same algorithm, upgraded key length)",
        "AES-128 is only Grover-weakened (effective ~64-bit strength), not broken; AES-256 restores full margin.",
        2.0,
        "No size change, negligible perf cost",
        "Universally supported",
    ),
}

SAFE_FAMILIES = {"ML-KEM", "ML-DSA", "SLH-DSA", "SPHINCS+", "FALCON"}


def recommend_for(
    artefact: CryptoArtefact,
    classification: ClassificationResult,
    risk: RiskResult,
) -> Recommendation:
    family = classification.algorithm_family

    if family in SAFE_FAMILIES or classification.vulnerability_tier == VulnerabilityTier.QUANTUM_SAFE:
        return Recommendation(
            artefact_id=artefact.id,
            current_algorithm=artefact.algorithm,
            recommended_algorithm=artefact.algorithm,
            rationale="Already quantum-resistant; no migration needed. Monitor for future NIST guidance updates.",
            latency_overhead_pct=0.0,
            key_or_sig_size_increase="N/A",
            library_maturity="N/A",
            priority=RiskTier.SAFE,
        )

    mapping = REPLACEMENT_MAP.get(family)
    if mapping is None:
        return Recommendation(
            artefact_id=artefact.id,
            current_algorithm=artefact.algorithm,
            recommended_algorithm="Manual review required",
            rationale=f"Unrecognised algorithm family '{family}'; not in the current mapping table.",
            latency_overhead_pct=None,
            key_or_sig_size_increase="Unknown",
            library_maturity="Unknown",
            priority=RiskTier.MEDIUM,
        )

    recommended, rationale, latency, size, maturity = mapping
    return Recommendation(
        artefact_id=artefact.id,
        current_algorithm=artefact.algorithm,
        recommended_algorithm=recommended,
        rationale=rationale,
        latency_overhead_pct=latency,
        key_or_sig_size_increase=size,
        library_maturity=maturity,
        priority=risk.risk_tier,
    )


def recommend_all(artefacts, classifications, risks):
    class_by_id = {c.artefact_id: c for c in classifications}
    risk_by_id = {r.artefact_id: r for r in risks}
    return [
        recommend_for(a, class_by_id[a.id], risk_by_id[a.id])
        for a in artefacts
    ]
