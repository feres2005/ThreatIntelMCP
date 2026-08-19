from scoring.scoring_service import (
    build_scoring_report,
)
from scoring.threat_scoring import (
    score_article_severity,
)
from database.cve_repository import (
    get_cve_details,
)
from database.mitre_repository import (
    get_mitre_technique_details,
)
from scoring.enrichment_mapping import (
    extract_cvss_scores,
)
from correlation.indicator_correlation_service import (
    correlate_indicator,
)


def _select_highest_article_severity(
    supporting_articles,
):
    if not isinstance(supporting_articles, list):
        return None

    selected_severity = None
    selected_points = 0

    for article in supporting_articles:
        if not isinstance(article, dict):
            continue

        severity = article.get("severity")
        component = score_article_severity(
            severity
        )

        if component["points"] > selected_points:
            selected_points = component["points"]
            selected_severity = severity

    return selected_severity


def _extract_related_values(
    related_entities,
    field_name,
):
    if not isinstance(related_entities, dict):
        return []

    entries = related_entities.get(field_name)

    if not isinstance(entries, list):
        return []

    values = []

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        value = entry.get("value")

        if isinstance(value, str) and value.strip():
            values.append(value)

    return values

def _build_related_cve_enrichment(
    related_entities,
):
    cve_ids = dict.fromkeys(
        _extract_related_values(
            related_entities,
            "cves",
        )
    )

    enrichment = []

    for cve_id in cve_ids:
        details = get_cve_details(cve_id)
        available = (
            isinstance(details, dict)
            and bool(details)
        )

        enrichment.append({
            "cve_id": cve_id,
            "enrichment_available": available,
            "details": (
                details if available else None
            ),
        })

    return enrichment


def _build_related_mitre_enrichment(
    related_entities,
):
    technique_ids = dict.fromkeys(
        _extract_related_values(
            related_entities,
            "mitre_techniques",
        )
    )

    enrichment = []

    for technique_id in technique_ids:
        details = get_mitre_technique_details(
            technique_id
        )

        available = (
            isinstance(details, dict)
            and bool(details)
        )

        enrichment.append({
            "technique_id": technique_id,
            "enrichment_available": available,
            "details": (
                details if available else None
            ),
        })

    return enrichment

def build_indicator_scoring_report(
    correlation,
    *,
    cve_enrichment=None,
    mitre_enrichment=None,
):
    if not isinstance(correlation, dict):
        raise ValueError(
            "Indicator correlation must be a dictionary."
        )

    indicator = correlation.get("indicator")
    indicator_type = correlation.get(
        "indicator_type"
    )

    if (
        not isinstance(indicator, str)
        or not indicator.strip()
    ):
        raise ValueError(
            "Indicator correlation is missing an indicator."
        )

    if (
        not isinstance(indicator_type, str)
        or not indicator_type.strip()
    ):
        raise ValueError(
            "Indicator correlation is missing an "
            "indicator type."
        )

    indicator = indicator.strip()
    indicator_type = indicator_type.strip()

    supporting_articles = correlation.get(
        "supporting_articles"
    )
    related_entities = correlation.get(
        "related_entities"
    )

    ai_confidences = []

    if isinstance(supporting_articles, list):
        for article in supporting_articles:
            if isinstance(article, dict):
                ai_confidences.append(
                    article.get("confidence_score")
                )

    scoring = build_scoring_report(
        article_severity=(
            _select_highest_article_severity(
                supporting_articles
            )
        ),
        cvss_scores=extract_cvss_scores(
            cve_enrichment
        ),
        otx_record=correlation.get(
            "otx_enrichment"
        ),
        malware=_extract_related_values(
            related_entities,
            "malware",
        ),
        apt_groups=_extract_related_values(
            related_entities,
            "apt_groups",
        ),
        mitre_techniques=_extract_related_values(
            related_entities,
            "mitre_techniques",
        ),
        article_ids=correlation.get(
            "supporting_article_ids"
        ),
        ai_confidences=ai_confidences,
        cve_enrichment=cve_enrichment,
        mitre_enrichment=mitre_enrichment,
        related_entities=related_entities,
    )

    return {
        "target": {
            "entity_type": "indicator",
            "indicator": indicator,
            "indicator_type": indicator_type,
        },
        **scoring,
    }

def score_indicator(
    indicator,
    include_otx=True,
):
    correlation = correlate_indicator(
        indicator,
        include_otx=include_otx,
    )

    related_entities = correlation.get(
        "related_entities"
    )

    cve_enrichment = (
        _build_related_cve_enrichment(
            related_entities
        )
    )

    mitre_enrichment = (
        _build_related_mitre_enrichment(
            related_entities
        )
    )

    return build_indicator_scoring_report(
        correlation,
        cve_enrichment=cve_enrichment,
        mitre_enrichment=mitre_enrichment,
    )