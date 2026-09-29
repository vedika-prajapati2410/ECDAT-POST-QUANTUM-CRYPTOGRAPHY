"""
Aggregation / Deduplication
=============================
Real scanners produce many raw *findings* -- the same weak pattern
(e.g. `AES-128` in a config loader) can turn up in dozens of files.
Presenting each occurrence as its own top-level artefact makes the
report noisy and unusable at scale, and is a clear "never tested on a
real codebase" tell.

This module groups raw findings into one artefact per distinct
(algorithm, type, name) fingerprint, merging their locations,
`used_by` sets, and data volumes, and keeps a total occurrence count.

Runs BEFORE classification/risk scoring -- everything downstream only
ever sees the merged, deduplicated artefact list.
"""


def _fingerprint(finding: dict) -> tuple:
    """
    Two raw findings are considered the same underlying artefact if
    they share a name, type and algorithm. Location is deliberately
    excluded from the fingerprint -- that's exactly what gets merged.
    """
    return (
        finding.get("name", "").strip().lower(),
        finding.get("type", "").strip().lower(),
        finding.get("algorithm", "").strip().upper(),
    )


def deduplicate(raw_findings: list) -> list:
    """
    Merge raw findings sharing a fingerprint into single artefact dicts.

    - `locations`: union of all locations the pattern was found at
    - `occurrence_count`: how many raw findings were merged
    - `used_by`: union across all merged findings
    - `data_volume_gb`: summed (each occurrence protects its own data)
    - `internet_facing`: True if ANY merged finding was internet-facing
                          (most conservative / worst-case merge)
    - `data_classification`: the most sensitive classification seen
                              (PII > financial > internal > public)
    - `confidence`: the LOWEST confidence seen across merged findings
                     (a single low-confidence hit shouldn't be hidden
                     by being averaged away with high-confidence ones)
    - all other scalar fields: taken from the first occurrence
    """
    if not raw_findings:
        return []

    sensitivity_rank = {"PII": 4, "financial": 3, "internal": 2, "public": 1}
    confidence_rank = {"low": 1, "medium": 2, "high": 3}

    groups = {}
    order = []  # preserve first-seen order for stable output

    for finding in raw_findings:
        key = _fingerprint(finding)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(finding)

    merged = []
    for key in order:
        members = groups[key]
        base = dict(members[0])  # start from the first occurrence's scalar fields

        all_locations = []
        all_used_by = []
        total_volume = 0.0
        any_internet_facing = False
        best_sensitivity = ("public", 0)
        worst_confidence = ("high", 3)

        for m in members:
            loc = m.get("location")
            if loc and loc not in all_locations:
                all_locations.append(loc)
            for u in m.get("used_by", []) or []:
                if u not in all_used_by:
                    all_used_by.append(u)
            total_volume += float(m.get("data_volume_gb", 0) or 0)
            any_internet_facing = any_internet_facing or bool(m.get("internet_facing", False))

            cls = m.get("data_classification", "internal")
            rank = sensitivity_rank.get(cls, 2)
            if rank > best_sensitivity[1]:
                best_sensitivity = (cls, rank)

            conf = str(m.get("confidence", "high")).lower()
            crank = confidence_rank.get(conf, 3)
            if crank < worst_confidence[1]:
                worst_confidence = (conf, crank)

        base["locations"] = all_locations
        base["location"] = all_locations[0] if all_locations else base.get("location", "unknown")
        base["occurrence_count"] = len(members)
        base["used_by"] = all_used_by
        base["data_volume_gb"] = round(total_volume, 2)
        base["internet_facing"] = any_internet_facing
        base["data_classification"] = best_sensitivity[0]
        base["confidence"] = worst_confidence[0]

        merged.append(base)

    return merged
