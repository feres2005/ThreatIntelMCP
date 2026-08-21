from sqlalchemy import text

from database.connection import engine


def get_pipeline_status_counts():
    query = text("""
        SELECT
            (
                SELECT COUNT(*)
                FROM articles
            ) AS total_articles,

            (
                SELECT COUNT(*)
                FROM articles
                WHERE processed IS TRUE
            ) AS processed_articles,

            (
                SELECT COUNT(*)
                FROM articles
                WHERE processed IS FALSE
            ) AS pending_articles,

            (
                SELECT COUNT(*)
                FROM article_analysis
            ) AS analyzed_articles,

            (
                SELECT COUNT(*)
                FROM articles
                LEFT JOIN article_analysis
                  ON article_analysis.article_id
                     = articles.id
                WHERE articles.processed IS TRUE
                  AND article_analysis.article_id
                      IS NULL
            ) AS processed_without_analysis,

            (
                SELECT COUNT(*)
                FROM articles
                JOIN article_analysis
                  ON article_analysis.article_id
                     = articles.id
                WHERE articles.processed IS FALSE
            ) AS pending_with_analysis,

            (
                SELECT COUNT(*)
                FROM article_iocs
            ) AS typed_ioc_rows,

            (
                SELECT COUNT(DISTINCT article_id)
                FROM article_iocs
            ) AS articles_with_typed_iocs,

            (
                SELECT COUNT(*)
                FROM intelligence_embeddings
                WHERE entity_type = 'article'
            ) AS article_embeddings,

            (
                SELECT COUNT(*)
                FROM articles
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM intelligence_embeddings
                    WHERE entity_type = 'article'
                      AND entity_id = articles.id::text
                )
            ) AS articles_missing_embeddings,

            (
                SELECT COUNT(*)
                FROM cve_enrichment
            ) AS enriched_cves,

            (
                SELECT COUNT(*)
                FROM otx_indicators
            ) AS cached_otx_indicators,

            (
                SELECT COUNT(*)
                FROM mitre_techniques
            ) AS mitre_techniques,

            (
                SELECT COUNT(*)
                FROM github_advisories
            ) AS github_advisories;
    """)

    with engine.connect() as connection:
        row = connection.execute(
            query
        ).mappings().one()

    return dict(row)
