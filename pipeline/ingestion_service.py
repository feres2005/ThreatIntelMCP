from collectors.rss_collector import collect_articles
from database.article_repository import (
    count_articles,
    insert_article,
)

def ingest_rss_articles():
    articles = collect_articles()

    inserted_article_ids = []
    existing_article_ids = []
    failures = []

    for position, article in enumerate(
        articles,
        start=1,
    ):
        try:
            result = insert_article(article)
        except Exception as error:
            failures.append({
                "position": position,
                "title": article.get("title"),
                "link": article.get("link"),
                "error": (
                    f"{type(error).__name__}: "
                    f"{error}"
                ),
            })
            continue

        article_id = result["article_id"]

        if result["inserted"]:
            inserted_article_ids.append(article_id)
        else:
            existing_article_ids.append(article_id)

    if failures:
        status = "completed_with_warnings"
    else:
        status = "completed"

    return {
        "operation": "rss_ingestion",
        "status": status,
        "collected_count": len(articles),
        "inserted_count": len(
            inserted_article_ids
        ),
        "existing_or_updated_count": len(
            existing_article_ids
        ),
        "failed_count": len(failures),
        "inserted_article_ids": (
            inserted_article_ids
        ),
        "existing_or_updated_article_ids": (
            existing_article_ids
        ),
        "failures": failures,
        "database_article_count": count_articles(),
    }
