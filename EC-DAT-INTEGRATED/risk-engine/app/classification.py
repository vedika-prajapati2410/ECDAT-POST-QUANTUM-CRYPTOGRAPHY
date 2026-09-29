"""
Classification Engine
======================
Takes raw CBOM artefacts and tags each one with:
  - algorithm family (RSA, ECC, AES, 3DES, ML-KEM, ML-DSA, ...)
  - quantum vulnerability tier (Shor-breakable / Grover-weakened / quantum-safe)
  - key-length adequacy (is the key long enough to matter at all, ignoring quantum)

This is deliberately rule-based (not ML) for hackathon reliability and
explainability -- judges can see exactly why something was flagged.
"""

from app.models import CryptoArtefact, ClassificationResult, VulnerabilityTier

# Minimum "classically adequate" key lengths (NIST SP 800-57 style baseline).
# Used only to catch already-weak crypto, independent of the quantum threat.
MIN_CLASSICAL_KEY_LENGTH = {
    "RSA": 2048,
    "DSA": 2048,
    "ECDSA": 224,
    "ECDH": 224,
    "AES": 128,
    "3DES": 168,
    "ML-KEM": 512,
    "ML-DSA": 44,
}

# Algorithm family -> quantum vulnerability tier.
# Shor's algorithm breaks integer factorisation & discrete log problems
# (RSA, DSA, ECC/ECDSA/ECDH, Diffie-Hellman) in polynomial time on a
# sufficiently large quantum computer.
# Grover's algorithm only *weakens* symmetric ciphers and hashes
# (quadratic speedup), so AES-256 stays safe but AES-128 effectively
# drops to ~64-bit strength -- treated as weakened, not broken.
FAMILY_VULNERABILITY = {
    "RSA": VulnerabilityTier.SHOR_BREAKABLE,
    "DSA": VulnerabilityTier.SHOR_BREAKABLE,
    "ECDSA": VulnerabilityTier.SHOR_BREAKABLE,
    "ECDH": VulnerabilityTier.SHOR_BREAKABLE,
    "DH": VulnerabilityTier.SHOR_BREAKABLE,
    "3DES": VulnerabilityTier.GROVER_WEAKENED,
    "DES": VulnerabilityTier.GROVER_WEAKENED,
    "AES": None,  # resolved dynamically based on key length (see below)
    "ML-KEM": VulnerabilityTier.QUANTUM_SAFE,
    "ML-DSA": VulnerabilityTier.QUANTUM_SAFE,
    "SLH-DSA": VulnerabilityTier.QUANTUM_SAFE,
    "SPHINCS+": VulnerabilityTier.QUANTUM_SAFE,
    "FALCON": VulnerabilityTier.QUANTUM_SAFE,
}


def _parse_algorithm(algorithm: str):
    """
    Split a string like "RSA-2048", "AES-128-GCM", "ML-KEM-768" into
    (family, key_length_hint). Best-effort -- falls back gracefully.
    """
    parts = algorithm.replace("_", "-").split("-")
    family = parts[0].upper()
    # handle "ML-KEM-768" / "ML-DSA-65" style two-token families
    if family == "ML" and len(parts) > 1:
        family = f"ML-{parts[1].upper()}"
        parts = parts[1:]
    if family in ("SLH", "SPHINCS+") and len(parts) > 1:
        family = "SLH-DSA"

    key_len = None
    for token in parts[1:]:
        if token.isdigit():
            key_len = int(token)
            break
    return family, key_len


def classify_artefact(artefact: CryptoArtefact) -> ClassificationResult:
    family, parsed_key_len = _parse_algorithm(artefact.algorithm)
    key_length = artefact.key_length or parsed_key_len

    if family == "AES":
        # Grover halves effective symmetric security; AES-256 is the
        # recommended floor for post-quantum-relevant symmetric use.
        tier = (
            VulnerabilityTier.QUANTUM_SAFE
            if key_length and key_length >= 256
            else VulnerabilityTier.GROVER_WEAKENED
        )
    else:
        tier = FAMILY_VULNERABILITY.get(family, VulnerabilityTier.UNKNOWN)

    min_len = MIN_CLASSICAL_KEY_LENGTH.get(family)
    adequate = True if min_len is None or key_length is None else key_length >= min_len

    notes = []
    if tier == VulnerabilityTier.SHOR_BREAKABLE:
        notes.append("Public-key algorithm; fully breakable by a sufficiently large quantum computer (Shor's algorithm).")
    elif tier == VulnerabilityTier.GROVER_WEAKENED:
        notes.append("Symmetric/legacy algorithm; effective security roughly halved under Grover's algorithm.")
    elif tier == VulnerabilityTier.QUANTUM_SAFE:
        notes.append("Believed quantum-resistant (NIST PQC standard or adequately-sized symmetric key).")
    else:
        notes.append("Unrecognised algorithm family; manual review recommended.")

    if not adequate:
        notes.append(f"Key length {key_length} is below the classical-security floor of {min_len} bits for {family}.")

    return ClassificationResult(
        artefact_id=artefact.id,
        algorithm_family=family,
        vulnerability_tier=tier,
        key_length_adequate=adequate,
        notes=" ".join(notes),
    )


def classify_all(artefacts):
    return [classify_artefact(a) for a in artefacts]
