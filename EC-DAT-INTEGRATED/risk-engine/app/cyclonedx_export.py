"""
CycloneDX CBOM Export
========================
The problem statement explicitly requires "a report displaying all
cryptographic assets ... in standardised formats." CycloneDX 1.6 added
a native Cryptographic Bill of Materials (CBOM) schema
(component.cryptoProperties) -- this module emits that format instead
of our internal JSON shape, so the output can be consumed by any
CycloneDX-compatible tool (Dependency-Track, etc.), not just our own
frontend.

Reference: https://cyclonedx.org/capabilities/cbom/
"""

from datetime import datetime, timezone
import uuid

# CycloneDX requires serialNumber to be a valid RFC 4122 UUID URN
# (urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx). Our scan_id is a
# short hex string, not a UUID, so we deterministically derive a real
# UUID5 from it (same scan_id always -> same serialNumber, but it's
# actually schema-valid) rather than splicing scan_id into the URN
# directly -- a real CycloneDX consumer (Dependency-Track etc.) would
# reject a malformed serialNumber outright.
_ECDAT_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # arbitrary fixed namespace, stable across runs


def _scan_uuid(scan_id: str) -> str:
    return str(uuid.uuid5(_ECDAT_NAMESPACE, scan_id))

CRYPTO_ASSET_TYPE_MAP = {
    "algorithm": "algorithm",
    "key": "related-crypto-material",
    "certificate": "certificate",
    "protocol": "protocol",
    "library": "algorithm",
}


def _algorithm_properties(artefact_dict, classification):
    return {
        "primitive": _infer_primitive(classification["algorithm_family"]),
        "parameterSetIdentifier": artefact_dict.get("algorithm"),
        "curve": artefact_dict.get("algorithm") if classification["algorithm_family"] in ("ECDSA", "ECDH") else None,
        "executionEnvironment": "software-plain-ram",
        "cryptoFunctions": _infer_functions(classification["algorithm_family"]),
        "classicalSecurityLevel": artefact_dict.get("key_length"),
        "nistQuantumSecurityLevel": 0 if classification["vulnerability_tier"] == "shor_breakable" else None,
    }


def _infer_primitive(family):
    return {
        "RSA": "pke", "DSA": "signature", "ECDSA": "signature", "ECDH": "key-agreement",
        "DH": "key-agreement", "AES": "block-cipher", "3DES": "block-cipher", "DES": "block-cipher",
        "ML-KEM": "kem", "ML-DSA": "signature", "SLH-DSA": "signature",
    }.get(family, "unknown")


def _infer_functions(family):
    return {
        "RSA": ["encrypt", "decrypt", "sign", "verify"],
        "DSA": ["sign", "verify"], "ECDSA": ["sign", "verify"],
        "ECDH": ["keygen", "keyderive"], "DH": ["keygen", "keyderive"],
        "AES": ["encrypt", "decrypt"], "3DES": ["encrypt", "decrypt"], "DES": ["encrypt", "decrypt"],
        "ML-KEM": ["keygen", "encapsulate", "decapsulate"],
        "ML-DSA": ["keygen", "sign", "verify"],
    }.get(family, [])


def build_cyclonedx_cbom(report: dict) -> dict:
    """
    Build a CycloneDX 1.6 BOM document (bomFormat CycloneDX) with one
    component per CBOM artefact, carrying cryptoProperties plus our
    risk/recommendation findings as CycloneDX `properties` extensions
    (namespaced under `ecdat:`) so nothing is lost in translation.
    """
    class_by_id = {c["artefact_id"]: c for c in report["classifications"]}
    risk_by_id = {r["artefact_id"]: r for r in report["risks"]}
    rec_by_id = {r["artefact_id"]: r for r in report["recommendations"]}

    components = []
    for artefact in report["cbom"]:
        aid = artefact["id"]
        classification = class_by_id[aid]
        risk = risk_by_id[aid]
        rec = rec_by_id[aid]

        components.append({
            "type": "cryptographic-asset",
            "bom-ref": aid,
            "name": artefact["name"],
            "cryptoProperties": {
                "assetType": CRYPTO_ASSET_TYPE_MAP.get(artefact["type"], "algorithm"),
                "algorithmProperties": _algorithm_properties(artefact, classification),
                "oid": None,
            },
            "properties": [
                {"name": "ecdat:location", "value": artefact["location"]},
                {"name": "ecdat:occurrence_count", "value": str(artefact.get("occurrence_count", 1))},
                {"name": "ecdat:confidence", "value": artefact.get("confidence", "high")},
                {"name": "ecdat:vulnerability_tier", "value": classification["vulnerability_tier"]},
                {"name": "ecdat:risk_tier", "value": risk["risk_tier"]},
                {"name": "ecdat:exposure_margin_years", "value": str(risk["exposure_margin_years"])},
                {"name": "ecdat:business_criticality", "value": risk["business_criticality"]},
                {"name": "ecdat:recommended_algorithm", "value": rec["recommended_algorithm"]},
                {"name": "ecdat:data_classification", "value": artefact["data_classification"]},
                {"name": "ecdat:internet_facing", "value": str(artefact["internet_facing"])},
            ],
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{_scan_uuid(report['scan_id'])}",
        "version": 1,
        "metadata": {
            "timestamp": report["created_at"],
            "tools": [{"vendor": "ECDAT", "name": "Enterprise Cryptographic Discovery & Analysis Tool", "version": "1.0"}],
            "properties": [
                {"name": "ecdat:years_to_crqc_assumption", "value": str(report["years_to_crqc_assumption"])},
                {"name": "ecdat:agility_score", "value": str(report["agility_score"]["score"])},
                {"name": "ecdat:generated_at", "value": datetime.now(timezone.utc).isoformat()},
            ],
        },
        "components": components,
    }
