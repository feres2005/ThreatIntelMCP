import pytest
from sqlalchemy import text

from database.connection import engine
from pipeline.curated_report_service import (
    ingest_curated_report,
)
from scripts.import_macsync_report import (
    MACSYNC_REPORT,
)
from scripts.import_twinloot_report import (
    TWINLOOT_REPORT,
)
import semantic_search.article_embedding_service as embedding_service


pytestmark = pytest.mark.integration


def test_macsync_report_is_stored_idempotently(
    monkeypatch,
):
    deterministic_embedding = (
        [1.0]
        + [0.0] * 383
    )

    monkeypatch.setattr(
        embedding_service,
        "generate_embedding",
        lambda text, text_type: (
            deterministic_embedding
        ),
    )

    first_result = ingest_curated_report(
        MACSYNC_REPORT
    )
    second_result = ingest_curated_report(
        MACSYNC_REPORT
    )

    assert first_result["status"] == "imported"
    assert first_result["inserted"] is True
    assert first_result["ioc_count"] == 31

    assert second_result["status"] == "imported"
    assert second_result["inserted"] is False
    assert second_result["article_id"] == (
        first_result["article_id"]
    )
    assert second_result["ioc_count"] == 31

    article_id = first_result["article_id"]

    with engine.connect() as connection:
        article = connection.execute(
            text(
                """
                SELECT
                    id,
                    source,
                    processed
                FROM articles
                WHERE link = :link
                """
            ),
            {
                "link": (
                    MACSYNC_REPORT[
                        "article"
                    ]["link"]
                ),
            },
        ).mappings().one()

        analysis = connection.execute(
            text(
                """
                SELECT
                    severity,
                    confidence_score,
                    malware,
                    mitre_techniques,
                    jsonb_array_length(iocs)
                        AS analysis_ioc_count
                FROM article_analysis
                WHERE article_id = :article_id
                """
            ),
            {"article_id": article_id},
        ).mappings().one()

        ioc_summary = connection.execute(
            text(
                """
                SELECT
                    COUNT(*) AS ioc_count,
                    COUNT(DISTINCT indicator)
                        AS distinct_indicator_count,
                    COUNT(DISTINCT indicator_type)
                        AS indicator_type_count,
                    MIN(indicator_type)
                        AS indicator_type
                FROM article_iocs
                WHERE article_id = :article_id
                """
            ),
            {"article_id": article_id},
        ).mappings().one()

        embedding_count = connection.execute(
            text(
                """
                SELECT COUNT(*)
                FROM intelligence_embeddings
                WHERE entity_type = 'article'
                  AND entity_id = :entity_id
                """
            ),
            {"entity_id": str(article_id)},
        ).scalar_one()

        article_count = connection.execute(
            text(
                """
                SELECT COUNT(*)
                FROM articles
                WHERE link = :link
                """
            ),
            {
                "link": (
                    MACSYNC_REPORT[
                        "article"
                    ]["link"]
                ),
            },
        ).scalar_one()

    assert article["id"] == article_id
    assert article["source"] == (
        "microsoft_security_blog"
    )
    assert article["processed"] is True
    assert article_count == 1

    assert analysis["severity"] == "High"
    assert float(
        analysis["confidence_score"]
    ) == 0.95
    assert analysis["malware"] == [
        "MacSync Stealer"
    ]
    assert analysis["mitre_techniques"] == [
        "T1059.004",
        "T1041",
    ]
    assert analysis["analysis_ioc_count"] == 31

    assert ioc_summary["ioc_count"] == 31
    assert (
        ioc_summary[
            "distinct_indicator_count"
        ]
        == 31
    )
    assert (
        ioc_summary["indicator_type_count"]
        == 1
    )
    assert ioc_summary["indicator_type"] == (
        "domain"
    )

    assert embedding_count == 1

def test_twinloot_report_is_stored_idempotently(
    monkeypatch,
):
    deterministic_embedding = (
        [1.0]
        + [0.0] * 383
    )

    monkeypatch.setattr(
        embedding_service,
        "generate_embedding",
        lambda text, text_type: (
            deterministic_embedding
        ),
    )

    first_result = ingest_curated_report(
        TWINLOOT_REPORT
    )
    second_result = ingest_curated_report(
        TWINLOOT_REPORT
    )

    assert first_result["status"] == "imported"
    assert first_result["inserted"] is True
    assert first_result["ioc_count"] == 9

    assert second_result["status"] == "imported"
    assert second_result["inserted"] is False
    assert second_result["article_id"] == (
        first_result["article_id"]
    )
    assert second_result["ioc_count"] == 9

    article_id = first_result["article_id"]

    with engine.connect() as connection:
        article = connection.execute(
            text(
                """
                SELECT
                    id,
                    source,
                    processed
                FROM articles
                WHERE link = :link
                """
            ),
            {
                "link": (
                    TWINLOOT_REPORT[
                        "article"
                    ]["link"]
                ),
            },
        ).mappings().one()

        analysis = connection.execute(
            text(
                """
                SELECT
                    severity,
                    confidence_score,
                    malware,
                    mitre_techniques,
                    jsonb_array_length(iocs)
                        AS analysis_ioc_count
                FROM article_analysis
                WHERE article_id = :article_id
                """
            ),
            {"article_id": article_id},
        ).mappings().one()

        ioc_rows = connection.execute(
            text(
                """
                SELECT
                    indicator,
                    indicator_type
                FROM article_iocs
                WHERE article_id = :article_id
                ORDER BY
                    indicator_type,
                    indicator
                """
            ),
            {"article_id": article_id},
        ).mappings().all()

        embedding_count = connection.execute(
            text(
                """
                SELECT COUNT(*)
                FROM intelligence_embeddings
                WHERE entity_type = 'article'
                  AND entity_id = :entity_id
                """
            ),
            {"entity_id": str(article_id)},
        ).scalar_one()

        article_count = connection.execute(
            text(
                """
                SELECT COUNT(*)
                FROM articles
                WHERE link = :link
                """
            ),
            {
                "link": (
                    TWINLOOT_REPORT[
                        "article"
                    ]["link"]
                ),
            },
        ).scalar_one()

    indicator_type_counts = {}

    for row in ioc_rows:
        indicator_type = row["indicator_type"]
        indicator_type_counts[indicator_type] = (
            indicator_type_counts.get(
                indicator_type,
                0,
            )
            + 1
        )

    stored_indicators = {
        row["indicator"]
        for row in ioc_rows
    }

    assert article["id"] == article_id
    assert article["source"] == "ontinue_research"
    assert article["processed"] is True
    assert article_count == 1

    assert analysis["severity"] == "High"
    assert float(
        analysis["confidence_score"]
    ) == 0.95
    assert analysis["malware"] == ["TWINLOOT"]
    assert analysis["analysis_ioc_count"] == 9

    assert len(ioc_rows) == 9
    assert indicator_type_counts == {
        "FileHash-SHA256": 4,
        "IPv4": 1,
        "domain": 4,
    }

    assert "193.24.211.221" in stored_indicators
    assert (
        "sharepointx.th2ch.com"
        in stored_indicators
    )
    assert (
        "2f1aa13fbdd8f5cdfe0838ecd4801a58"
        "81239ea096dd80f0af6ad1990c11418e"
        in stored_indicators
    )

    assert embedding_count == 1