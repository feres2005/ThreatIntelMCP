def extract_cvss_scores(cve_enrichment):
    if not isinstance(cve_enrichment, list):
        return []

    cvss_scores = []

    for entry in cve_enrichment:
        if not isinstance(entry, dict):
            continue

        if entry.get("enrichment_available") is not True:
            continue

        details = entry.get("details")

        if (
            isinstance(details, dict)
            and "cvss_score" in details
        ):
            cvss_scores.append(
                details["cvss_score"]
            )

    return cvss_scores