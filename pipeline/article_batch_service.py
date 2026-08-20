from database.article_repository import (
    get_articles_by_ids,
    get_unprocessed_articles_by_ids,
)
from pipeline.article_processing_service import (
    process_article,
)


SUCCESS_STATUSES = {
    "processed",
    "processed_with_warnings",
}


def process_article_batch(
    article_ids,
    *,
    limit=5,
    include_otx=True,
    include_cve=True,
    reanalyze=False,
    progress_callback=None,
):
    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or limit <= 0
    ):
        raise ValueError(
            "Batch limit must be a "
            "positive integer."
        )

    if not isinstance(include_otx, bool):
        raise ValueError(
            "include_otx must be a boolean."
        )

    if not isinstance(include_cve, bool):
        raise ValueError(
            "include_cve must be a boolean."
        )

    if not isinstance(reanalyze, bool):
        raise ValueError(
            "reanalyze must be a boolean."
        )

    if (
        progress_callback is not None
        and not callable(progress_callback)
    ):
        raise ValueError(
            "Progress callback must be "
            "callable or None."
        )

    if reanalyze:
        articles = get_articles_by_ids(
            article_ids
        )
        selection_mode = "explicit_reanalysis"
    else:
        articles = (
            get_unprocessed_articles_by_ids(
                article_ids
            )
        )
        selection_mode = "unprocessed_only"
    

    unique_article_ids = list(
        dict.fromkeys(article_ids)
    )

    selected_articles = articles[:limit]

    results = []

    total_selected = len(selected_articles)

    for position, article in enumerate(
        selected_articles,
        start=1,
    ):
        if progress_callback is not None:
            progress_callback({
                "event": "started",
                "position": position,
                "total": total_selected,
                "article_id": article.id,
                "title": article.title,
            })

        try:
            result = process_article(
                article,
                include_otx=include_otx,
                include_cve=include_cve,
            )
        except Exception as error:
            result = {
                "article_id": article.id,
                "status": "failed",
                "error": (
                    f"{type(error).__name__}: "
                    f"{error}"
                ),
                "marked_processed": False,
                "warnings": [
                    "Mandatory article processing "
                    "failed."
                ],
            }

        results.append(result)

        if progress_callback is not None:
            progress_callback({
                "event": "finished",
                "position": position,
                "total": total_selected,
                "article_id": article.id,
                "title": article.title,
                "status": result["status"],
            })

    status_counts = {}

    for result in results:
        status = result["status"]

        status_counts[status] = (
            status_counts.get(status, 0)
            + 1
        )

    successful_count = sum(
        result["status"] in SUCCESS_STATUSES
        for result in results
    )

    return {
        "selection_mode": selection_mode,
        "eligible_article_count": len(
            articles
        ),
        "ineligible_or_missing_count": (
            len(unique_article_ids)
            - len(articles)
        ),
        
        "requested_article_count": len(
            unique_article_ids
        ),
        "available_unprocessed_count": len(
            articles
        ),
        "selected_article_count": len(
            selected_articles
        ),
        "deferred_article_count": (
            len(articles)
            - len(selected_articles)
        ),
        "unavailable_or_processed_count": (
            len(unique_article_ids)
            - len(articles)
        ),
        "successful_count": successful_count,
        "unsuccessful_count": (
            len(results)
            - successful_count
        ),
        "status_counts": status_counts,
        "results": results,
    }