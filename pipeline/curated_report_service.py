from database.article_ioc_repository import (
    replace_article_iocs,
)
from database.article_repository import (
    insert_article,
    mark_article_as_processed,
    save_article_analysis,
)
from enrichment.ioc_normalizer import (
    normalize_ioc_list,
)
from semantic_search.article_embedding_service import (
    index_article,
)
INVALID_CURATED_IOCS_MESSAGE = (
    "Curated report IOCs must be a non-empty "
    "list of valid, unique indicators."
)


def _normalize_curated_iocs(iocs):
    if not isinstance(iocs, list) or not iocs:
        raise ValueError(
            INVALID_CURATED_IOCS_MESSAGE
        )

    normalized_iocs = normalize_ioc_list(iocs)

    if len(normalized_iocs) != len(iocs):
        raise ValueError(
            INVALID_CURATED_IOCS_MESSAGE
        )

    normalized_keys = {
        (
            ioc["indicator"],
            ioc["indicator_type"],
        )
        for ioc in normalized_iocs
    }

    if len(normalized_keys) != len(iocs):
        raise ValueError(
            INVALID_CURATED_IOCS_MESSAGE
        )

    return normalized_iocs

def ingest_curated_report(report):
    normalized_iocs = _normalize_curated_iocs(
        report.get("iocs")
    )

    insertion_result = insert_article(
        report["article"]
    )
    article_id = insertion_result["article_id"]

    analysis = dict(report["analysis"])
    analysis["article_id"] = article_id
    analysis["iocs"] = [
        ioc["indicator"]
        for ioc in normalized_iocs
    ]

    save_article_analysis(analysis)

    ioc_replacement = replace_article_iocs(
        article_id,
        normalized_iocs,
    )

    mark_article_as_processed(article_id)

    embedding_result = index_article(article_id)

    return {
        "status": "imported",
        "article_id": article_id,
        "inserted": insertion_result["inserted"],
        "ioc_count": len(normalized_iocs),
        "ioc_replacement": ioc_replacement,
        "embedding_status": embedding_result["status"],
    }