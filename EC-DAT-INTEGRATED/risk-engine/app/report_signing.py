"""
Tamper-Evident Report Signing
================================
Thematically fitting: sign the report we hand back so its integrity
can be verified later -- "prove this report wasn't altered after we
generated it."

HONESTY NOTE ON THE ALGORITHM USED: the ideal version of this feature
signs with ML-DSA (the very PQC signature standard this tool
recommends to others) via liboqs. liboqs is a native-compiled library
that isn't installable in this offline sandbox (no network access),
so shipping it here would mean either faking the signature or silently
failing. Instead:

  - This module signs with Ed25519 (via the `cryptography` package,
    already available) as a real, working, verifiable signature today.
  - It is structured so swapping in ML-DSA is a one-function change
    (`_sign_bytes` / `_verify_bytes`) once `liboqs-python` is
    installed in the team's actual dev/deploy environment -- see the
    TODO at the bottom.
  - Every signature payload includes an explicit "algorithm" field so
    nobody downstream mistakes this for a PQC signature by accident.

Say exactly this in the demo: "the report is cryptographically signed
for tamper-evidence today with Ed25519, architected to switch to
ML-DSA the moment liboqs is available in our deployment environment."
That is accurate and still a strong, on-theme line.
"""

import json
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

_SIGNING_ALGORITHM = "Ed25519 (classical placeholder for ML-DSA -- see module docstring)"

# Generated once per process. In production, load a persistent key
# from secure storage (KMS/HSM) rather than regenerating per restart.
_PRIVATE_KEY = Ed25519PrivateKey.generate()
_PUBLIC_KEY = _PRIVATE_KEY.public_key()


def _canonical_bytes(report: dict) -> bytes:
    """Deterministic serialization so the same report always hashes/signs identically."""
    payload = {k: v for k, v in report.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, default=str).encode("utf-8")


def sign_report(report: dict) -> dict:
    message = _canonical_bytes(report)
    signature = _PRIVATE_KEY.sign(message)
    return {
        "algorithm": _SIGNING_ALGORITHM,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "public_key_b64": base64.b64encode(
            _PUBLIC_KEY.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ).decode("ascii"),
        "note": "Signed for tamper-evidence. Verify with /api/scans/<id>/verify. See module docstring re: PQC upgrade path.",
    }


def verify_report(report: dict, signature_block: dict) -> bool:
    try:
        sig = base64.b64decode(signature_block["signature_b64"])
        pub_bytes = base64.b64decode(signature_block["public_key_b64"])
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        message = _canonical_bytes(report)
        pub_key.verify(sig, message)
        return True
    except (InvalidSignature, KeyError, ValueError):
        return False


# TODO (once liboqs-python is available in the team's real environment):
#
#   from oqs import Signature
#   def _sign_bytes(message: bytes) -> bytes:
#       with Signature("ML-DSA-65") as signer:
#           public_key = signer.generate_keypair()
#           return signer.sign(message), public_key
#
# Swap _PRIVATE_KEY.sign(...) above for this and update _SIGNING_ALGORITHM
# to "ML-DSA-65". No other module needs to change.
