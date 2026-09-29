"""
Certificate Deep Analysis
============================
X.509 certificates carry risk independent of the quantum question:
expired certs, self-signed certs in production, and weak *signature*
algorithms (separate from the key-exchange algorithm) are all classic
findings a general "algorithm scanner" would miss.

Only runs on artefacts of type "certificate".
"""

from datetime import date, datetime
from app.models import AssetType, CertificateFinding

WEAK_SIGNATURE_ALGORITHMS = {"MD5", "SHA1", "SHA-1"}


def analyze_certificate(artefact) -> CertificateFinding:
    issues = []
    days_until_expiry = None

    if artefact.expiry_date:
        try:
            expiry = datetime.strptime(artefact.expiry_date, "%Y-%m-%d").date()
            days_until_expiry = (expiry - date.today()).days
            if days_until_expiry < 0:
                issues.append(f"Expired {abs(days_until_expiry)} days ago")
            elif days_until_expiry < 30:
                issues.append(f"Expires in {days_until_expiry} days -- renew urgently")
            elif days_until_expiry < 90:
                issues.append(f"Expires in {days_until_expiry} days -- plan renewal")
        except ValueError:
            issues.append(f"Unparseable expiry_date '{artefact.expiry_date}' (expected YYYY-MM-DD)")

    if artefact.self_signed:
        issues.append("Self-signed certificate in use -- verify this is intentional (e.g. internal mTLS) and not accidental production exposure")

    if artefact.signature_algorithm:
        sig = artefact.signature_algorithm.upper().replace("WITH", "").replace("RSA", "").replace("ECDSA", "").strip("-")
        for weak in WEAK_SIGNATURE_ALGORITHMS:
            if weak.replace("-", "") in artefact.signature_algorithm.upper().replace("-", ""):
                issues.append(f"Weak certificate signature hash ({artefact.signature_algorithm}) -- collision-prone, migrate to SHA-256 or better")
                break

    return CertificateFinding(
        artefact_id=artefact.id,
        issues=issues,
        expiry_date=artefact.expiry_date,
        days_until_expiry=days_until_expiry,
    )


def analyze_all(artefacts) -> list:
    return [
        analyze_certificate(a)
        for a in artefacts
        if a.type == AssetType.CERTIFICATE and (a.expiry_date or a.self_signed is not None or a.signature_algorithm)
    ]
