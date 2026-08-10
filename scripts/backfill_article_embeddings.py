from semantic_search.article_embedding_service import index_missing_articles

BATCH_LIMIT=25

def backfill_article_embeddings():
    total_created = 0
    batch_number = 1

    while True:
        results = index_missing_articles(BATCH_LIMIT)

        if not results:
            break

        created_count = sum(
            result["status"] == "created"
            for result in results
        )
        total_created += created_count

        print(
            f"Batch {batch_number}: "
            f"created {created_count} embeddings."
        )

        batch_number += 1

    print(
        f"Backfill completed. "
        f"Created {total_created} article embeddings."
    )
if __name__ == "__main__":
    backfill_article_embeddings()