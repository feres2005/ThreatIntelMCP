
from database.correlation_repository import (
    get_article_correlation_data,
    get_article_ids_by_indicator,
)
from enrichment.ioc_normalizer import normalize_ioc
from enrichment.otx_lookup_service import (
    lookup_otx_indicator,
)
from correlation.entity_validation import (
    normalize_entity_value,
)

CORRELATION_FIELDS = (
    "cves",
    "malware",
    "mitre_techniques",
    "apt_groups",
    "targeted_sectors",
    "affected_technologies",
)




def _collect_entity_evidence(
    article_correlations,
    field_name,
):
    evidence_by_value = {}

    for correlation in article_correlations:
        article = correlation["article"]
        values = article.get(field_name)

        if not isinstance(values, list):
            continue

        for value in values:
            cleaned_value = normalize_entity_value(
                field_name,
                value,
            )

            if cleaned_value is None:
                continue

            comparison_key = cleaned_value.casefold()
            article_id = article["article_id"]

            evidence = evidence_by_value.setdefault(
                comparison_key,
                {
                    "value": cleaned_value,
                    "supporting_article_ids": [],
                },
            )

            if article_id not in evidence[
                "supporting_article_ids"
            ]:
                evidence[
                    "supporting_article_ids"
                ].append(article_id)

    results = []

    for evidence in sorted(
        evidence_by_value.values(),
        key=lambda item: item["value"].casefold(),
    ):
        results.append({
            "value": evidence["value"],
            "supporting_article_count": len(
                evidence["supporting_article_ids"]
            ),
            "supporting_article_ids": evidence[
                "supporting_article_ids"
            ],
        })

    return results

def correlate_indicator(indicator,include_otx=True):
    normalized = normalize_ioc(indicator)

    if normalized is None:
        raise ValueError(
            "A valid supported IOC is required."
        )


    otx_enrichment = None

    if include_otx:
      otx_enrichment = lookup_otx_indicator(
            normalized["indicator"],
            normalized["indicator_type"],
        )

    article_ids = get_article_ids_by_indicator(
        normalized["indicator"],
        normalized["indicator_type"],
    )

    article_correlations = []

    for article_id in article_ids:
        correlation = get_article_correlation_data(
            article_id
        )

        if correlation is not None:
            article_correlations.append(correlation)

    supporting_articles = []


    for correlation in article_correlations:
        article = correlation["article"]

        supporting_articles.append({
            "article_id": article["article_id"],
            "title": article["title"],
            "link": article["link"],
            "published": article["published"],
            "severity": article["severity"],
            "confidence_score": article[
                "confidence_score"
            ],
        })

    related_entities = {
      field_name: _collect_entity_evidence(
          article_correlations,
          field_name,
        )
      for field_name in CORRELATION_FIELDS
    }

    return {
        "indicator": normalized["indicator"],
        "indicator_type": normalized["indicator_type"],
        "supporting_article_count": len(article_ids),
        "supporting_article_ids": article_ids,
        "supporting_articles": supporting_articles,
        "related_entities": related_entities,
        "otx_enrichment": otx_enrichment,
    }