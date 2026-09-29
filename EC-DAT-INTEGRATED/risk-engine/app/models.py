"""
Core data structures for the CBOM Analytics pipeline.

We keep these as plain dataclasses (no pydantic dependency) so the
logic layer stays framework-agnostic -- it can sit behind Flask,
FastAPI, or be called directly from a CLI/notebook.

The artefact schema is a simplified, CBOM-flavoured subset of the
CycloneDX CBOM spec (https://cyclonedx.org/capabilities/cbom/).
Field names are chosen to map cleanly onto CycloneDX later:
  - "algorithm"   -> component.cryptoProperties.algorithmProperties
  - "type"        -> component.cryptoProperties.assetType
  - "used_by"     -> dependency graph edges
"""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class AssetType(str, Enum):
    ALGORITHM = "algorithm"
    KEY = "key"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    LIBRARY = "library"


class VulnerabilityTier(str, Enum):
    SHOR_BREAKABLE = "shor_breakable"      # public-key crypto: RSA, ECC, DH, DSA
    GROVER_WEAKENED = "grover_weakened"     # symmetric crypto with insufficient key length
    QUANTUM_SAFE = "quantum_safe"           # NIST PQC algorithms, or symmetric w/ adequate length
    UNKNOWN = "unknown"


class RiskTier(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    SAFE = "Safe"


class Confidence(str, Enum):
    """
    How sure the scanner is that a detected pattern is a real crypto
    usage vs. a false positive (e.g. the literal string "AES" inside a
    comment or variable name, rather than an actual cipher call).
    """
    HIGH = "high"     # e.g. resolved API call: Cipher.getInstance("AES/CBC/PKCS5Padding")
    MEDIUM = "medium"  # e.g. matched via config file / string constant, not a direct call site
    LOW = "low"       # e.g. heuristic/keyword match only, needs manual review


@dataclass
class CryptoArtefact:
    """A single discovered cryptographic artefact (raw CBOM input)."""
    id: str
    name: str
    type: AssetType
    algorithm: str                      # e.g. "RSA-2048", "AES-128-GCM", "ECDSA-P256", "ML-KEM-768"
    location: str                       # primary/first file path / service / repo
    key_length: Optional[int] = None
    internet_facing: bool = False
    data_classification: str = "internal"   # "PII" | "financial" | "internal" | "public"
    data_volume_gb: float = 0.0
    used_by: list = field(default_factory=list)   # downstream service/component names
    first_seen: str = ""

    # --- aggregation / dedup ---
    locations: list = field(default_factory=list)   # all locations this pattern was found at
    occurrence_count: int = 1

    # --- confidence scoring ---
    confidence: Confidence = Confidence.HIGH

    # --- library-specific (for CVE cross-referencing) ---
    library_name: Optional[str] = None
    library_version: Optional[str] = None

    # --- certificate-specific (for cert deep analysis) ---
    issuer: Optional[str] = None
    expiry_date: Optional[str] = None       # ISO date string "YYYY-MM-DD"
    self_signed: Optional[bool] = None
    signature_algorithm: Optional[str] = None

    def __post_init__(self):
        if isinstance(self.confidence, str):
            self.confidence = Confidence(self.confidence)
        if not self.locations:
            self.locations = [self.location]

    def to_dict(self):
        d = dict(self.__dict__)
        d["type"] = self.type.value if isinstance(self.type, AssetType) else self.type
        d["confidence"] = self.confidence.value if isinstance(self.confidence, Confidence) else self.confidence
        return d


@dataclass
class ClassificationResult:
    artefact_id: str
    algorithm_family: str
    vulnerability_tier: VulnerabilityTier
    key_length_adequate: bool
    notes: str = ""


@dataclass
class RiskResult:
    artefact_id: str
    x_data_shelf_life_years: float
    y_migration_time_years: float
    z_years_to_crqc: float
    exposure_margin_years: float   # Z - (X + Y); negative == at risk
    at_risk: bool
    risk_tier: RiskTier
    business_criticality: str
    confidence: str = "high"
    confidence_capped: bool = False   # True if the raw computed tier was downgraded due to low confidence


@dataclass
class RegulatoryFlag:
    artefact_id: str
    frameworks: list             # e.g. ["DPDP Act 2023", "CERT-In Directions 2022"]
    reason: str


@dataclass
class CveFinding:
    artefact_id: str
    cve_id: str
    severity: str                # "Critical" | "High" | "Medium" | "Low"
    description: str
    affected_version: str


@dataclass
class CertificateFinding:
    artefact_id: str
    issues: list                 # list of strings, e.g. ["Expired", "Self-signed"]
    expiry_date: Optional[str]
    days_until_expiry: Optional[int]


@dataclass
class TriageOverride:
    artefact_id: str
    status: str                  # "accepted_risk" | "false_positive" | "confirmed"
    justification: str
    reviewer: str
    timestamp: str


@dataclass
class Recommendation:
    artefact_id: str
    current_algorithm: str
    recommended_algorithm: str
    rationale: str
    latency_overhead_pct: Optional[float]
    key_or_sig_size_increase: str
    library_maturity: str
    priority: RiskTier
