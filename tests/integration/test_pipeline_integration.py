"""Deterministic pipeline integration tests using isolated PostgreSQL."""
from datetime import datetime, timezone
import requests
import pytest
from sqlalchemy import text
import enrichment.otx_lookup_service as otx_lookup_service
import pipeline.article_batch_service as batch_service
import pipeline.ingestion_service as ingestion_service
from database.connection import engine
import collectors.otx_collector as otx_collector
import enrichment.cve_lookup_service as cve_lookup_service
import pipeline.article_processing_service as processing_service
import semantic_search.embedding_service as embedding_service
from database.article_repository import (
    get_unprocessed_articles_by_ids,
)
from fastapi.testclient import TestClient

import mcp_server.server as mcp_server
from api.app import app

pytestmark = pytest.mark.integration


CONTROLLED_ARTICLE = {
    "title": "Controlled ransomware campaign",
    "link": (
        "https://integration.test/"
        "articles/controlled-ransomware"
    ),
    "published": datetime(
        2026,
        8,
        22,
        12,
        0,
        tzinfo=timezone.utc,
    ),
    "summary": (
        "A controlled ransomware report containing "
        "malicious.example and CVE-2026-12345."
    ),
    "source": "integration_fixture",
}

def controlled_analysis(article):
    return {
        "article_id": article.id,
        "summary": "Controlled AI threat analysis.",
        "classification": ["ransomware"],
        "severity": "High",
        "confidence_score": 0.92,
        "iocs": [
            "MALICIOUS[.]EXAMPLE",
            "malicious.example",
            "not an indicator",
        ],
        "cves": ["CVE-2026-12345"],
        "malware": ["ControlledRansom"],
        "mitre_techniques": [],
        "apt_groups": ["APT29"],
        "targeted_sectors": ["Finance"],
        "affected_technologies": ["Windows"],
    }


def controlled_nvd_response(cve_id):
    assert cve_id == "CVE-2026-12345"

    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Controlled CVE fixture.",
                        }
                    ],
                    "published": "2026-08-20T10:00:00",
                    "lastModified": "2026-08-21T10:00:00",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                }
                            }
                        ]
                    },
                    "references": [],
                }
            }
        ]
    }


def controlled_otx_response(
    indicator,
    indicator_type,
):
    assert indicator == "malicious.example"
    assert indicator_type == "domain"

    return {
        "reputation": -1,
        "pulse_info": {
            "count": 12,
            "related": {},
        },
        "country_name": "Controlled Country",
        "country_code": "CC",
        "asn": "AS64500",
        "validation": [],
        "sections": ["general"],
    }


class ControlledEmbedding:
    def tolist(self):
        return [0.01] * 384


class ControlledEmbeddingModel:
    def encode(
        self,
        text,
        normalize_embeddings,
    ):
        assert text.startswith("passage: ")
        assert normalize_embeddings is True
        return ControlledEmbedding()


def test_successful_full_chain(monkeypatch):
    monkeypatch.setattr(
        ingestion_service,
        "collect_articles",
        lambda: [CONTROLLED_ARTICLE],
    )

    ingestion_result = (
        ingestion_service.ingest_rss_articles()
    )

    assert ingestion_result["status"] == "completed"
    assert ingestion_result["collected_count"] == 1
    assert ingestion_result["inserted_count"] == 1
    assert ingestion_result["existing_or_updated_count"] == 0
    assert ingestion_result["failed_count"] == 0
    assert ingestion_result["database_article_count"] == 1

    article_id = ingestion_result[
        "inserted_article_ids"
    ][0]

    with engine.connect() as connection:
        stored_article = connection.execute(
            text(
                """
                SELECT
                    id,
                    title,
                    link,
                    source,
                    processed
                FROM articles
                WHERE id = :article_id
                """
            ),
            {"article_id": article_id},
        ).mappings().one()

    assert stored_article["id"] == article_id
    assert stored_article["title"] == (
        CONTROLLED_ARTICLE["title"]
    )
    assert stored_article["link"] == (
        CONTROLLED_ARTICLE["link"]
    )
    assert stored_article["source"] == (
        CONTROLLED_ARTICLE["source"]
    )
    assert stored_article["processed"] is False

    monkeypatch.setattr(
        processing_service,
        "analyze_article",
        controlled_analysis,
    )
    monkeypatch.setattr(
        cve_lookup_service,
        "fetch_cve_from_nvd",
        controlled_nvd_response,
    )
    monkeypatch.setattr(
        otx_collector,
        "fetch_otx_indicator",
        controlled_otx_response,
    )
    monkeypatch.setattr(
        embedding_service,
        "get_embedding_model",
        lambda: ControlledEmbeddingModel(),
    )

    pending_articles = (
        get_unprocessed_articles_by_ids(
            [article_id]
        )
    )

    assert len(pending_articles) == 1
    assert pending_articles[0].id == article_id

    processing_result = (
        processing_service.process_article(
            pending_articles[0],
            include_otx=True,
            include_cve=True,
        )
    )

    assert processing_result["status"] == "processed"
    assert processing_result["marked_processed"] is True
    assert processing_result["warnings"] == []
    assert processing_result[
        "ioc_processing"
    ]["normalized_iocs"] == [
        {
            "indicator": "malicious.example",
            "indicator_type": "domain",
        }
    ]
    assert processing_result[
        "otx_enrichment"
    ]["successful_lookup_count"] == 1
    assert processing_result[
        "cve_enrichment"
    ]["available_count"] == 1
    assert processing_result[
        "embedding_status"
    ] == "created"
    with engine.connect() as connection:
        stored_state = connection.execute(
            text(
                """
                SELECT
                    articles.processed,
                    article_analysis.summary,
                    article_analysis.severity,
                    article_analysis.confidence_score,
                    article_analysis.classification,
                    article_analysis.cves,
                    article_analysis.malware
                FROM articles
                JOIN article_analysis
                    ON article_analysis.article_id = articles.id
                WHERE articles.id = :article_id
                """
            ),
            {"article_id": article_id},
        ).mappings().one()

        stored_counts = connection.execute(
            text(
                """
                SELECT
                    (SELECT COUNT(*) FROM articles)
                        AS article_count,
                    (SELECT COUNT(*) FROM article_analysis)
                        AS analysis_count,
                    (SELECT COUNT(*) FROM article_iocs)
                        AS ioc_count,
                    (SELECT COUNT(*) FROM cve_enrichment)
                        AS cve_count,
                    (SELECT COUNT(*) FROM otx_indicators)
                        AS otx_count,
                    (SELECT COUNT(*) FROM intelligence_embeddings)
                        AS embedding_count
                """
            )
        ).mappings().one()

        stored_ioc = connection.execute(
            text(
                """
                SELECT indicator, indicator_type
                FROM article_iocs
                WHERE article_id = :article_id
                """
            ),
            {"article_id": article_id},
        ).mappings().one()

        stored_cve = connection.execute(
            text(
                """
                SELECT cve_id, cvss_score, severity
                FROM cve_enrichment
                WHERE cve_id = :cve_id
                """
            ),
            {"cve_id": "CVE-2026-12345"},
        ).mappings().one()

        stored_otx = connection.execute(
            text(
                """
                SELECT indicator, indicator_type, pulse_count
                FROM otx_indicators
                WHERE indicator = :indicator
                """
            ),
            {"indicator": "malicious.example"},
        ).mappings().one()

        stored_embedding = connection.execute(
            text(
                """
                SELECT
                    entity_type,
                    entity_id,
                    embedding_model,
                    content_hash,
                    vector_dims(embedding) AS dimensions
                FROM intelligence_embeddings
                WHERE entity_type = :entity_type
                  AND entity_id = :entity_id
                """
            ),
            {
                "entity_type": "article",
                "entity_id": str(article_id),
            },
        ).mappings().one()

    assert stored_state["processed"] is True
    assert stored_state["summary"] == (
        "Controlled AI threat analysis."
    )
    assert stored_state["severity"] == "High"
    assert float(
        stored_state["confidence_score"]
    ) == 0.92
    assert stored_state["classification"] == [
        "ransomware"
    ]
    assert stored_state["cves"] == [
        "CVE-2026-12345"
    ]
    assert stored_state["malware"] == [
        "ControlledRansom"
    ]

    assert dict(stored_counts) == {
        "article_count": 1,
        "analysis_count": 1,
        "ioc_count": 1,
        "cve_count": 1,
        "otx_count": 1,
        "embedding_count": 1,
    }

    assert dict(stored_ioc) == {
        "indicator": "malicious.example",
        "indicator_type": "domain",
    }
    assert stored_cve["cve_id"] == "CVE-2026-12345"
    assert float(stored_cve["cvss_score"]) == 9.8
    assert stored_cve["severity"] == "CRITICAL"
    assert stored_otx["indicator"] == "malicious.example"
    assert stored_otx["indicator_type"] == "domain"
    assert stored_otx["pulse_count"] == 12

    assert stored_embedding["entity_type"] == "article"
    assert stored_embedding["entity_id"] == str(article_id)
    assert stored_embedding["embedding_model"] == (
        "intfloat/multilingual-e5-small"
    )
    assert stored_embedding["content_hash"]
    assert stored_embedding["dimensions"] == 384

    with TestClient(app) as client:
        rest_response = client.get(
            f"/api/v1/articles/{article_id}/score",
            params={"include_otx": "true"},
        )

    assert rest_response.status_code == 200

    rest_scoring = rest_response.json()

    mcp_scoring = (
        mcp_server.score_threat_article(
            article_id,
            include_otx=True,
        )
    )

    assert mcp_scoring is not None

    assert rest_scoring[
        "target"
    ]["article_id"] == article_id
    assert mcp_scoring[
        "target"
    ]["article_id"] == article_id

    assert rest_scoring[
        "threat"
    ]["threat_score"] == 72.4
    assert rest_scoring[
        "threat"
    ]["threat_score"] == mcp_scoring[
        "threat"
    ]["threat_score"]

    assert rest_scoring[
        "confidence"
    ]["confidence_score"] == 63.0
    assert rest_scoring[
        "confidence"
    ]["confidence_score"] == mcp_scoring[
        "confidence"
    ]["confidence_score"]

    assert rest_scoring[
        "priority"
    ]["priority_code"] == "P1"
    assert rest_scoring["priority"] == (
        mcp_scoring["priority"]
    )

    assert rest_scoring["warnings"] == []
    assert rest_scoring["warnings"] == (
        mcp_scoring["warnings"]
    )
    assert rest_scoring[
        "threat"
    ]["warnings"] == mcp_scoring[
        "threat"
    ]["warnings"]
    assert rest_scoring[
        "confidence"
    ]["warnings"] == mcp_scoring[
        "confidence"
    ]["warnings"]

    with engine.begin() as connection:
        connection.execute(
            text(
                """
                UPDATE article_analysis
                SET severity = :severity
                WHERE article_id = :article_id
                """
            ),
            {
                "severity": "Unexpected",
                "article_id": article_id,
            },
        )

    with TestClient(app) as client:
        warning_response = client.get(
            f"/api/v1/articles/{article_id}/score",
            params={"include_otx": "true"},
        )

    warning_mcp_scoring = (
        mcp_server.score_threat_article(
            article_id,
            include_otx=True,
        )
    )

    expected_warning = {
        "source": "threat",
        "message": (
            "Unsupported article severity was "
            "treated as unknown."
        ),
    }

    assert warning_response.status_code == 200
    assert warning_response.json()["warnings"] == [
        expected_warning
    ]
    assert warning_mcp_scoring["warnings"] == [
        expected_warning
    ]
    assert warning_response.json()[
        "threat"
    ]["warnings"] == warning_mcp_scoring[
        "threat"
    ]["warnings"]

def test_optional_external_failures_produce_warnings(
    monkeypatch,
):
    monkeypatch.setattr(
        ingestion_service,
        "collect_articles",
        lambda: [CONTROLLED_ARTICLE],
    )

    ingestion_result = (
        ingestion_service.ingest_rss_articles()
    )
    article_id = ingestion_result[
        "inserted_article_ids"
    ][0]

    monkeypatch.setattr(
        processing_service,
        "analyze_article",
        controlled_analysis,
    )

    def fail_nvd(cve_id):
        raise requests.RequestException(
            "Controlled NVD outage."
        )

    def fail_otx(
        indicator,
        indicator_type,
    ):
        raise requests.RequestException(
            "Controlled OTX outage."
        )

    def fail_embedding_model():
        raise RuntimeError(
            "Controlled embedding model failure."
        )

    monkeypatch.setattr(
        cve_lookup_service,
        "fetch_cve_from_nvd",
        fail_nvd,
    )
    monkeypatch.setattr(
        otx_collector,
        "fetch_otx_indicator",
        fail_otx,
    )
    monkeypatch.setattr(
        embedding_service,
        "get_embedding_model",
        fail_embedding_model,
    )

    pending_article = (
        get_unprocessed_articles_by_ids(
            [article_id]
        )[0]
    )

    result = processing_service.process_article(
        pending_article,
        include_otx=True,
        include_cve=True,
    )

    assert result["status"] == (
        "processed_with_warnings"
    )
    assert result["marked_processed"] is True
    assert result["warnings"] == [
        (
            "One or more OTX lookups "
            "returned no enrichment."
        ),
        "One or more CVE lookups failed.",
        "Article embedding refresh failed.",
    ]

    assert result[
        "otx_enrichment"
    ]["failed_lookup_count"] == 1
    assert result[
        "cve_enrichment"
    ]["failed_count"] == 1
    assert result[
        "embedding_status"
    ] == "failed"

    with engine.connect() as connection:
        stored_result = connection.execute(
            text(
                """
                SELECT
                    articles.processed,
                    (
                        SELECT COUNT(*)
                        FROM article_analysis
                    ) AS analysis_count,
                    (
                        SELECT COUNT(*)
                        FROM article_iocs
                    ) AS ioc_count,
                    (
                        SELECT COUNT(*)
                        FROM cve_enrichment
                    ) AS cve_count,
                    (
                        SELECT COUNT(*)
                        FROM otx_indicators
                    ) AS otx_count,
                    (
                        SELECT COUNT(*)
                        FROM intelligence_embeddings
                    ) AS embedding_count
                FROM articles
                WHERE articles.id = :article_id
                """
            ),
            {"article_id": article_id},
        ).mappings().one()

    assert dict(stored_result) == {
        "processed": True,
        "analysis_count": 1,
        "ioc_count": 1,
        "cve_count": 0,
        "otx_count": 0,
        "embedding_count": 0,
    }
def test_stale_enrichment_cache_survives_external_outages(
    monkeypatch,
):
    monkeypatch.setattr(
        cve_lookup_service,
        "fetch_cve_from_nvd",
        controlled_nvd_response,
    )
    monkeypatch.setattr(
        otx_collector,
        "fetch_otx_indicator",
        controlled_otx_response,
    )

    initial_cve = cve_lookup_service.lookup_cve(
        "CVE-2026-12345"
    )
    initial_otx = (
        otx_lookup_service.lookup_otx_indicator(
            "malicious.example",
            "domain",
        )
    )

    assert initial_cve is not None
    assert initial_otx is not None

    with engine.begin() as connection:
        connection.execute(
            text(
                """
                UPDATE cve_enrichment
                SET enriched_at =
                    CURRENT_TIMESTAMP - INTERVAL '2 days'
                WHERE cve_id = :cve_id
                """
            ),
            {"cve_id": "CVE-2026-12345"},
        )
        connection.execute(
            text(
                """
                UPDATE otx_indicators
                SET last_checked =
                    CURRENT_TIMESTAMP - INTERVAL '2 days'
                WHERE indicator = :indicator
                  AND indicator_type = :indicator_type
                """
            ),
            {
                "indicator": "malicious.example",
                "indicator_type": "domain",
            },
        )

    monkeypatch.setattr(
        cve_lookup_service,
        "fetch_cve_from_nvd",
        lambda cve_id: None,
    )

    def fail_otx_refresh(
        indicator,
        indicator_type,
    ):
        raise requests.RequestException(
            "Controlled OTX refresh outage."
        )

    monkeypatch.setattr(
        otx_collector,
        "fetch_otx_indicator",
        fail_otx_refresh,
    )

    fallback_cve = cve_lookup_service.lookup_cve(
        "CVE-2026-12345"
    )
    fallback_otx = (
        otx_lookup_service.lookup_otx_indicator(
            "malicious.example",
            "domain",
        )
    )

    assert fallback_cve is not None
    assert fallback_cve["cve_id"] == (
        initial_cve["cve_id"]
    )
    assert fallback_cve["cvss_score"] == (
        initial_cve["cvss_score"]
    )
    assert fallback_cve["severity"] == (
        initial_cve["severity"]
    )

    assert fallback_otx is not None
    assert fallback_otx["indicator"] == (
        initial_otx["indicator"]
    )
    assert fallback_otx["indicator_type"] == (
        initial_otx["indicator_type"]
    )
    assert fallback_otx["pulse_count"] == (
        initial_otx["pulse_count"]
    )

    with engine.connect() as connection:
        stored_counts = connection.execute(
            text(
                """
                SELECT
                    (SELECT COUNT(*) FROM cve_enrichment)
                        AS cve_count,
                    (SELECT COUNT(*) FROM otx_indicators)
                        AS otx_count
                """
            )
        ).mappings().one()

    assert dict(stored_counts) == {
        "cve_count": 1,
        "otx_count": 1,
    }

def test_failed_analysis_can_retry_without_duplicates(
    monkeypatch,
):
    monkeypatch.setattr(
        ingestion_service,
        "collect_articles",
        lambda: [CONTROLLED_ARTICLE],
    )

    first_ingestion = (
        ingestion_service.ingest_rss_articles()
    )
    second_ingestion = (
        ingestion_service.ingest_rss_articles()
    )

    article_id = first_ingestion[
        "inserted_article_ids"
    ][0]

    assert first_ingestion["inserted_count"] == 1
    assert second_ingestion["inserted_count"] == 0
    assert second_ingestion[
        "existing_or_updated_count"
    ] == 1
    assert second_ingestion[
        "existing_or_updated_article_ids"
    ] == [article_id]
    assert second_ingestion[
        "database_article_count"
    ] == 1

    monkeypatch.setattr(
        processing_service,
        "analyze_article",
        lambda article: None,
    )

    pending_article = (
        get_unprocessed_articles_by_ids(
            [article_id]
        )[0]
    )

    failed_result = (
        processing_service.process_article(
            pending_article,
            include_otx=True,
            include_cve=True,
        )
    )

    assert failed_result["status"] == (
        "analysis_failed"
    )
    assert failed_result["marked_processed"] is False
    assert failed_result[
        "embedding_status"
    ] == "deferred"

    with engine.connect() as connection:
        failed_state = connection.execute(
            text(
                """
                SELECT
                    articles.processed,
                    (
                        SELECT COUNT(*)
                        FROM article_analysis
                    ) AS analysis_count,
                    (
                        SELECT COUNT(*)
                        FROM article_iocs
                    ) AS ioc_count,
                    (
                        SELECT COUNT(*)
                        FROM intelligence_embeddings
                    ) AS embedding_count
                FROM articles
                WHERE articles.id = :article_id
                """
            ),
            {"article_id": article_id},
        ).mappings().one()

    assert dict(failed_state) == {
        "processed": False,
        "analysis_count": 0,
        "ioc_count": 0,
        "embedding_count": 0,
    }

    monkeypatch.setattr(
        processing_service,
        "analyze_article",
        controlled_analysis,
    )
    monkeypatch.setattr(
        cve_lookup_service,
        "fetch_cve_from_nvd",
        controlled_nvd_response,
    )
    monkeypatch.setattr(
        otx_collector,
        "fetch_otx_indicator",
        controlled_otx_response,
    )
    monkeypatch.setattr(
        embedding_service,
        "get_embedding_model",
        lambda: ControlledEmbeddingModel(),
    )

    retry_article = (
        get_unprocessed_articles_by_ids(
            [article_id]
        )[0]
    )

    successful_retry = (
        processing_service.process_article(
            retry_article,
            include_otx=True,
            include_cve=True,
        )
    )

    assert successful_retry["status"] == "processed"
    assert successful_retry[
        "marked_processed"
    ] is True
    assert successful_retry[
        "embedding_status"
    ] == "created"

    repeated_retry = (
        batch_service.process_article_batch(
            [article_id],
            limit=1,
            include_otx=True,
            include_cve=True,
            reanalyze=True,
        )
    )

    assert repeated_retry["successful_count"] == 1
    assert repeated_retry["results"][0]["status"] == (
        "processed"
    )
    assert repeated_retry[
        "results"
    ][0]["embedding_status"] == "unchanged"

    with engine.connect() as connection:
        final_counts = connection.execute(
            text(
                """
                SELECT
                    (SELECT COUNT(*) FROM articles)
                        AS article_count,
                    (SELECT COUNT(*) FROM article_analysis)
                        AS analysis_count,
                    (SELECT COUNT(*) FROM article_iocs)
                        AS ioc_count,
                    (SELECT COUNT(*) FROM cve_enrichment)
                        AS cve_count,
                    (SELECT COUNT(*) FROM otx_indicators)
                        AS otx_count,
                    (SELECT COUNT(*) FROM intelligence_embeddings)
                        AS embedding_count
                """
            )
        ).mappings().one()

        processed = connection.execute(
            text(
                """
                SELECT processed
                FROM articles
                WHERE id = :article_id
                """
            ),
            {"article_id": article_id},
        ).scalar_one()

    assert processed is True
    assert dict(final_counts) == {
        "article_count": 1,
        "analysis_count": 1,
        "ioc_count": 1,
        "cve_count": 1,
        "otx_count": 1,
        "embedding_count": 1,
    }
def test_mandatory_failure_does_not_report_success(
    monkeypatch,
):
    monkeypatch.setattr(
        ingestion_service,
        "collect_articles",
        lambda: [CONTROLLED_ARTICLE],
    )

    ingestion_result = (
        ingestion_service.ingest_rss_articles()
    )
    article_id = ingestion_result[
        "inserted_article_ids"
    ][0]

    def invalid_analysis(article):
        analysis = controlled_analysis(article)
        analysis["iocs"] = "not-a-list"
        return analysis

    monkeypatch.setattr(
        processing_service,
        "analyze_article",
        invalid_analysis,
    )

    batch_result = (
        batch_service.process_article_batch(
            [article_id],
            limit=1,
            include_otx=False,
            include_cve=False,
        )
    )

    assert batch_result["successful_count"] == 0
    assert batch_result["unsuccessful_count"] == 1
    assert batch_result["status_counts"] == {
        "failed": 1
    }

    failure = batch_result["results"][0]

    assert failure["article_id"] == article_id
    assert failure["status"] == "failed"
    assert failure["marked_processed"] is False
    assert failure["warnings"] == [
        "Mandatory article processing failed."
    ]
    assert failure["error"] == (
        "ValueError: IOC values must be "
        "provided as a list."
    )

    with engine.connect() as connection:
        stored_state = connection.execute(
            text(
                """
                SELECT
                    articles.processed,
                    (
                        SELECT COUNT(*)
                        FROM article_analysis
                    ) AS analysis_count,
                    (
                        SELECT COUNT(*)
                        FROM article_iocs
                    ) AS ioc_count,
                    (
                        SELECT COUNT(*)
                        FROM intelligence_embeddings
                    ) AS embedding_count
                FROM articles
                WHERE articles.id = :article_id
                """
            ),
            {"article_id": article_id},
        ).mappings().one()

    assert dict(stored_state) == {
        "processed": False,
        "analysis_count": 1,
        "ioc_count": 0,
        "embedding_count": 0,
    }
