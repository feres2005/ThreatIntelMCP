from database.correlation_repository import (
    get_article_correlation_data,
)
from enrichment.otx_lookup_service import (
    lookup_otx_indicators,
)

from correlation.entity_validation import (
    normalize_entity_list,
)
from database.cve_repository import get_cve_details
from database.mitre_repository import (
    get_mitre_technique_details,
)

MAX_CVE_DESCRIPTION_LENGTH = 1000

def _summarize_text(value, max_length):
    if not isinstance(value, str):
        return value, False

    normalized_value = " ".join(value.split())

    if len(normalized_value) <= max_length:
        return normalized_value, False

    summary = (
        normalized_value[:max_length - 3].rstrip()
        + "..."
    )

    return summary, True

def _build_cve_enrichment(cve_ids):
    results = []

    for cve_id in cve_ids:
        details = get_cve_details(cve_id)

        if details is None:
            results.append({
                "cve_id": cve_id,
                "enrichment_available": False,
                "details": None,
            })
            continue

        description, description_truncated = (
            _summarize_text(
                details.get("description"),
                MAX_CVE_DESCRIPTION_LENGTH,
            )
        )

        results.append({
            "cve_id": cve_id,
            "enrichment_available": True,
            "details": {
                "description": description,
                "description_truncated": (
                    description_truncated
                ),
                "cvss_score": details.get(
                    "cvss_score"
                ),
                "severity": details.get(
                    "severity"
                ),
                "published": details.get(
                    "published"
                ),
                "last_modified": details.get(
                    "last_modified"
                ),
                "vendors": details.get("vendors"),
                "products": details.get("products"),
                "weaknesses": details.get(
                    "weaknesses"
                ),
            },
        })

    return results

def _build_mitre_enrichment(
    technique_ids,
):
    results = []

    for technique_id in technique_ids:
        details = get_mitre_technique_details(
            technique_id
        )

        if details is None:
            results.append({
                "technique_id": technique_id,
                "enrichment_available": False,
                "details": None,
            })
            continue

        results.append({
            "technique_id": technique_id,
            "enrichment_available": True,
            "details": {
                "name": details.get("name"),
                "domain": details.get("domain"),
                "is_subtechnique": details.get(
                    "is_subtechnique"
                ),
                "platforms": details.get(
                    "platforms"
                ),
                "kill_chain_phases": details.get(
                    "kill_chain_phases"
                ),
                "version": details.get("version"),
                "revoked": details.get("revoked"),
                "deprecated": details.get(
                    "deprecated"
                ),
            },
        })

    return results


def get_article_investigation(
    article_id,
    include_otx=True,
):
    if (
        not isinstance(article_id, int) or isinstance(article_id, bool) or article_id <= 0):
        raise ValueError(
            "Article ID must be a positive integer."
        )
    correlation = get_article_correlation_data(
        article_id
    )

    if correlation is None:
        return None

    typed_iocs = correlation["typed_iocs"]

    article = correlation["article"]

    cve_ids = normalize_entity_list(
        "cves",
        article.get("cves"),
    )

    cve_enrichment = _build_cve_enrichment(
        cve_ids
    )

    technique_ids = normalize_entity_list(
        "mitre_techniques",
        article.get("mitre_techniques"),
    )

    mitre_enrichment = _build_mitre_enrichment(
        technique_ids
    )

    otx_results = [None] * len(typed_iocs)

    if include_otx and typed_iocs:
        otx_results = lookup_otx_indicators(
            typed_iocs
        )

    ioc_enrichment = []

    for ioc, otx_result in zip(
        typed_iocs,
        otx_results,
    ):
        ioc_enrichment.append({
            "indicator": ioc["indicator"],
            "indicator_type": ioc[
                "indicator_type"
            ],
            "otx_enrichment": otx_result,
        })

    return {
        "article": correlation["article"],
        "typed_iocs": typed_iocs,
        "ioc_enrichment": ioc_enrichment,
        "cve_enrichment": cve_enrichment,
        "mitre_enrichment": mitre_enrichment,
    }