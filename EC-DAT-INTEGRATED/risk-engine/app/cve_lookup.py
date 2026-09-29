"""
CVE Cross-Referencing (library artefacts only)
=================================================
Independent of the quantum-readiness question: a scanned library might
also be running a version with a KNOWN, CLASSICAL vulnerability today.

HONESTY NOTE: this is a small, curated, illustrative starter dataset
of well-known historical CVEs -- NOT a live feed from the National
Vulnerability Database (NVD). It is deliberately conservative (only
includes CVEs that are widely documented and version-bounded) so we
never fabricate a CVE ID or a false match. In a production build,
replace `_KNOWN_VULNERABLE_VERSIONS` with a live NVD/OSV.dev API
lookup keyed on package name + version (see TODO at bottom).
"""

import re
from app.models import CveFinding

# library_name (lowercase) -> list of (version_predicate, cve_id, severity, description)
# version_predicate is a simple "< X.Y.Z" style string checked with _version_lt.
_KNOWN_VULNERABLE_VERSIONS = {
    "openssl": [
        ("< 1.1.1", "CVE-2021-3450", "High",
         "X509_V_FLAG_X509_STRICT bypass allowing certificate chain verification bypass."),
        ("< 1.0.2", "CVE-2016-2107", "High",
         "Padding oracle in AES-NI CBC MAC checking, allowing plaintext recovery via MITM."),
        ("< 1.1.1n", "CVE-2022-0778", "High",
         "Infinite loop in BN_mod_sqrt() reachable via malformed certificate (DoS)."),
    ],
    "log4j": [
        ("< 2.17.0", "CVE-2021-44228", "Critical",
         "JNDI lookup remote code execution ('Log4Shell')."),
    ],
    "struts": [
        ("< 2.3.32", "CVE-2017-5638", "Critical",
         "Jakarta Multipart parser RCE via crafted Content-Type header."),
    ],
    "openssh": [
        ("< 7.4", "CVE-2016-10009", "High",
         "Untrusted search path / agent-forwarding privilege escalation."),
    ],
}


def _version_tuple(v: str):
    return tuple(int(p) for p in re.findall(r"\d+", v))


def _version_lt(installed: str, bound: str) -> bool:
    try:
        return _version_tuple(installed) < _version_tuple(bound)
    except (ValueError, TypeError):
        return False


def lookup_cves(artefact) -> list:
    if not artefact.library_name or not artefact.library_version:
        return []

    key = artefact.library_name.strip().lower()
    entries = _KNOWN_VULNERABLE_VERSIONS.get(key)
    if not entries:
        return []

    findings = []
    for predicate, cve_id, severity, description in entries:
        bound = predicate.replace("<", "").strip()
        if _version_lt(artefact.library_version, bound):
            findings.append(CveFinding(
                artefact_id=artefact.id,
                cve_id=cve_id,
                severity=severity,
                description=description,
                affected_version=f"{artefact.library_name} {artefact.library_version} (fixed in {bound})",
            ))
    return findings


def lookup_all(artefacts) -> list:
    findings = []
    for a in artefacts:
        findings.extend(lookup_cves(a))
    return findings


# TODO (post-hackathon): replace the static table above with a live lookup, e.g.:
#
#   import requests
#   def lookup_live(package: str, version: str):
#       resp = requests.post("https://api.osv.dev/v1/query", json={
#           "package": {"name": package, "ecosystem": "..."},
#           "version": version,
#       })
#       return resp.json().get("vulns", [])
#
# Left as static/offline for the hackathon build since it must run
# without network access and without an NVD API key.
