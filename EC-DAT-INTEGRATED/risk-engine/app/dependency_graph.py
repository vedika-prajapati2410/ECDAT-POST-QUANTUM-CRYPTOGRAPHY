"""
USP #4: Dependency Chain Risk Propagation (Blast Radius)
============================================================
Most scanners flag a vulnerable artefact in isolation. This module
answers "if this crypto artefact is compromised/broken, how far does
that spread?" -- surfacing blast radius, not just an occurrence count.
Feeds nicely into a graph visualisation on the frontend.
"""

from app.models import RiskTier


def build_blast_radius(artefacts, risks):
    """
    For each at-risk artefact, blast_radius = number of distinct
    downstream services/components listed in `used_by`. We also
    compute an org-wide edge list so the frontend can render a graph.
    """
    risk_by_id = {r.artefact_id: r for r in risks}
    nodes = []
    edges = []
    blast_radius_report = []

    for artefact in artefacts:
        risk = risk_by_id[artefact.id]
        nodes.append({
            "id": artefact.id,
            "label": artefact.name,
            "risk_tier": risk.risk_tier.value,
        })
        for downstream in artefact.used_by:
            edges.append({"from": artefact.id, "to": downstream})

        if risk.risk_tier in (RiskTier.CRITICAL, RiskTier.HIGH):
            blast_radius_report.append({
                "artefact_id": artefact.id,
                "name": artefact.name,
                "risk_tier": risk.risk_tier.value,
                "blast_radius": len(set(artefact.used_by)),
                "downstream_components": sorted(set(artefact.used_by)),
            })

    blast_radius_report.sort(key=lambda x: x["blast_radius"], reverse=True)

    return {
        "graph": {"nodes": nodes, "edges": edges},
        "highest_blast_radius": blast_radius_report,
    }
