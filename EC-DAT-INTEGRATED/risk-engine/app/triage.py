"""
Manual Triage / Override Workflow
====================================
Automated scanners are never 100% right. A security reviewer needs to
be able to mark a finding "accepted risk" (business decision to defer)
or "false positive" (scanner was wrong), with a justification, and
have that override respected in the report and in the Agility Score --
otherwise the tool cries wolf forever and reviewers start ignoring it.

Overrides are stored per artefact_id, keyed by scan_id (an override
is scoped to a specific scan; re-running the scanner and getting a
new scan_id means findings need re-triage unless the frontend carries
overrides forward -- deliberate, since a re-scan might have new code
at that same location).
"""

from datetime import datetime, timezone
from app.models import TriageOverride, RiskTier

VALID_STATUSES = {"accepted_risk", "false_positive", "confirmed"}


def apply_overrides(risks: list, overrides: dict) -> list:
    """
    `risks` is the list of risk dicts already in the report.
    `overrides` is {artefact_id: TriageOverride-shaped dict}.
    Returns a NEW list with `risk_tier` adjusted and an `triage` block
    attached -- does not mutate the input.
    """
    adjusted = []
    for r in risks:
        r = dict(r)
        override = overrides.get(r["artefact_id"])
        if override:
            r["triage"] = override
            if override["status"] == "false_positive":
                r["risk_tier"] = RiskTier.SAFE.value
                r["at_risk"] = False
            elif override["status"] == "accepted_risk":
                # Keep the tier visible (so it's not hidden from the
                # inventory) but flag it clearly as a knowing exception.
                r["accepted_risk"] = True
        adjusted.append(r)
    return adjusted


def make_override(artefact_id: str, status: str, justification: str, reviewer: str) -> dict:
    if status not in VALID_STATUSES:
        raise ValueError(f"status must be one of {sorted(VALID_STATUSES)}, got '{status}'")
    if not justification or not justification.strip():
        raise ValueError("justification is required -- overrides must be auditable, not silent")
    override = TriageOverride(
        artefact_id=artefact_id,
        status=status,
        justification=justification.strip(),
        reviewer=reviewer or "unspecified",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    return vars(override)
