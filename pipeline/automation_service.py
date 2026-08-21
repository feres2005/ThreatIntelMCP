from database.article_repository import (
    get_unprocessed_articles,
)
from pipeline.article_batch_service import (
    process_article_batch,
)
from database.pipeline_status_repository import (
    get_pipeline_status_counts,
)
from semantic_search.article_embedding_service import (
    index_missing_articles,
)
from collectors.github_collector import (
    synchronize_all_github_advisories,
)
from collectors.mitre_collector import (
    collect_mitre_techniques,
)

MAX_PROCESSING_BATCH_SIZE = 20
MAX_EMBEDDING_BATCH_SIZE = 100

EMBEDDING_SUCCESS_STATUSES = {
    "created",
    "updated",
    "unchanged",
}
MITRE_DOMAINS = (
    "enterprise-attack",
    "mobile-attack",
    "ics-attack",
)

def _calculate_percentage(value, total):
    if total == 0:
        return 0.0

    return round(
        value / total * 100,
        2,
    )

def process_pending_articles(
    limit=5,
    *,
    include_otx=False,
    include_cve=False,
):
    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or limit <= 0
    ):
        raise ValueError(
            "Processing limit must be a "
            "positive integer."
        )

    if limit > MAX_PROCESSING_BATCH_SIZE:
        raise ValueError(
            "Processing limit cannot exceed "
            f"{MAX_PROCESSING_BATCH_SIZE}."
        )

    if not isinstance(include_otx, bool):
        raise ValueError(
            "include_otx must be a boolean."
        )

    if not isinstance(include_cve, bool):
        raise ValueError(
            "include_cve must be a boolean."
        )

    pending_articles = get_unprocessed_articles(
        limit
    )

    article_ids = [
        article.id
        for article in pending_articles
    ]

    batch_result = process_article_batch(
        article_ids,
        limit=limit,
        include_otx=include_otx,
        include_cve=include_cve,
        reanalyze=False,
    )

    return {
        "operation": "process_pending_articles",
        "requested_limit": limit,
        "selected_article_ids": article_ids,
        **batch_result,
    }

def index_pending_embeddings(limit=25):
    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or limit <= 0
    ):
        raise ValueError(
            "Embedding limit must be a "
            "positive integer."
        )

    if limit > MAX_EMBEDDING_BATCH_SIZE:
        raise ValueError(
            "Embedding limit cannot exceed "
            f"{MAX_EMBEDDING_BATCH_SIZE}."
        )

    results = index_missing_articles(limit)

    status_counts = {}

    for result in results:
        status = result["status"]

        status_counts[status] = (
            status_counts.get(status, 0)
            + 1
        )

    successful_count = sum(
        result["status"]
        in EMBEDDING_SUCCESS_STATUSES
        for result in results
    )

    return {
        "operation": "index_pending_embeddings",
        "requested_limit": limit,
        "selected_count": len(results),
        "successful_count": successful_count,
        "unsuccessful_count": (
            len(results) - successful_count
        ),
        "status_counts": status_counts,
        "results": results,
    }

def get_pipeline_status():
    counts = get_pipeline_status_counts()

    total_articles = counts["total_articles"]

    embedded_articles = (
        total_articles
        - counts["articles_missing_embeddings"]
    )

    warnings = []

    if counts["processed_without_analysis"] > 0:
        warnings.append(
            f'{counts["processed_without_analysis"]} '
            "processed articles have no AI analysis."
        )

    if counts["pending_with_analysis"] > 0:
        warnings.append(
            f'{counts["pending_with_analysis"]} '
            "pending articles already have AI analysis."
        )

    if warnings:
        health_status = "attention_required"
    else:
        health_status = "healthy"

    return {
        "operation": "get_pipeline_status",
        "health_status": health_status,
        "work_pending": {
            "article_processing": (
                counts["pending_articles"]
            ),
            "embedding_indexing": (
                counts[
                    "articles_missing_embeddings"
                ]
            ),
        },
        "coverage": {
            "processing_percent": (
                _calculate_percentage(
                    counts["processed_articles"],
                    total_articles,
                )
            ),
            "analysis_percent": (
                _calculate_percentage(
                    counts["analyzed_articles"],
                    total_articles,
                )
            ),
            "embedding_percent": (
                _calculate_percentage(
                    embedded_articles,
                    total_articles,
                )
            ),
        },
        "counts": counts,
        "warnings": warnings,
    }

def synchronize_mitre_intelligence(
    domains=None,
):
    if domains is None:
        selected_domains = list(
            MITRE_DOMAINS
        )
    else:
        if not isinstance(domains, list):
            raise ValueError(
                "MITRE domains must be "
                "provided as a list."
            )

        if not domains:
            raise ValueError(
                "At least one MITRE domain "
                "is required."
            )

        selected_domains = []

        for domain in domains:
            if (
                not isinstance(domain, str)
                or domain not in MITRE_DOMAINS
            ):
                raise ValueError(
                    "Unsupported MITRE domain: "
                    f"{domain!r}."
                )

            if domain not in selected_domains:
                selected_domains.append(domain)

    results = []

    for domain in selected_domains:
        try:
            saved_count = (
                collect_mitre_techniques(
                    domain
                )
            )
        except Exception as error:
            results.append({
                "domain": domain,
                "status": "failed",
                "saved_technique_count": 0,
                "error": (
                    f"{type(error).__name__}: "
                    f"{error}"
                ),
            })
            continue

        results.append({
            "domain": domain,
            "status": "synchronized",
            "saved_technique_count": (
                saved_count
            ),
        })

    successful_domain_count = sum(
        result["status"] == "synchronized"
        for result in results
    )

    failed_domain_count = (
        len(results)
        - successful_domain_count
    )

    if failed_domain_count == 0:
        status = "completed"
    elif successful_domain_count == 0:
        status = "failed"
    else:
        status = "completed_with_warnings"

    return {
        "operation": (
            "synchronize_mitre_intelligence"
        ),
        "status": status,
        "requested_domains": selected_domains,
        "successful_domain_count": (
            successful_domain_count
        ),
        "failed_domain_count": (
            failed_domain_count
        ),
        "total_saved_techniques": sum(
            result["saved_technique_count"]
            for result in results
        ),
        "results": results,
    }


def synchronize_github_intelligence():
    return synchronize_all_github_advisories()
