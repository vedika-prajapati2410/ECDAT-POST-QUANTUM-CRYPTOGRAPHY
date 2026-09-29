"""
Trend / Diff Analysis
========================
Turns the tool from a one-time auditor into a continuous-monitoring
product: "since your last scan, 3 new vulnerable artefacts were
introduced, 5 were remediated, Agility Score moved +4.2." Reuses the
stored scan history -- no new scanning logic needed.
"""


def diff_reports(older: dict, newer: dict) -> dict:
    older_ids = {a["id"] for a in older["cbom"]}
    newer_ids = {a["id"] for a in newer["cbom"]}

    older_by_id = {a["id"]: a for a in older["cbom"]}
    newer_by_id = {a["id"]: a for a in newer["cbom"]}

    older_risk_by_id = {r["artefact_id"]: r for r in older["risks"]}
    newer_risk_by_id = {r["artefact_id"]: r for r in newer["risks"]}

    new_artefact_ids = newer_ids - older_ids
    removed_artefact_ids = older_ids - newer_ids
    common_ids = newer_ids & older_ids

    newly_introduced = [
        {"id": aid, "name": newer_by_id[aid]["name"], "risk_tier": newer_risk_by_id[aid]["risk_tier"]}
        for aid in new_artefact_ids
    ]
    removed = [
        {"id": aid, "name": older_by_id[aid]["name"]}
        for aid in removed_artefact_ids
    ]

    improved, worsened, unchanged = [], [], []
    severity_order = {"Safe": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    for aid in common_ids:
        old_tier = older_risk_by_id[aid]["risk_tier"]
        new_tier = newer_risk_by_id[aid]["risk_tier"]
        if severity_order[new_tier] < severity_order[old_tier]:
            improved.append({"id": aid, "name": newer_by_id[aid]["name"], "from": old_tier, "to": new_tier})
        elif severity_order[new_tier] > severity_order[old_tier]:
            worsened.append({"id": aid, "name": newer_by_id[aid]["name"], "from": old_tier, "to": new_tier})
        else:
            unchanged.append(aid)

    score_delta = round(newer["agility_score"]["score"] - older["agility_score"]["score"], 1)

    return {
        "older_scan_id": older["scan_id"],
        "newer_scan_id": newer["scan_id"],
        "agility_score_delta": score_delta,
        "agility_score_trend": "improving" if score_delta > 0 else "declining" if score_delta < 0 else "flat",
        "newly_introduced_artefacts": newly_introduced,
        "removed_or_remediated_artefacts": removed,
        "risk_improved": improved,
        "risk_worsened": worsened,
        "unchanged_count": len(unchanged),
        "headline": _headline(score_delta, newly_introduced, improved, worsened),
    }


def _headline(score_delta, newly_introduced, improved, worsened):
    parts = []
    if score_delta != 0:
        direction = "improved" if score_delta > 0 else "declined"
        parts.append(f"Agility Score {direction} by {abs(score_delta)} points")
    if newly_introduced:
        parts.append(f"{len(newly_introduced)} new artefact(s) introduced")
    if improved:
        parts.append(f"{len(improved)} artefact(s) remediated/improved")
    if worsened:
        parts.append(f"{len(worsened)} artefact(s) regressed")
    return "; ".join(parts) if parts else "No material change since the previous scan."
