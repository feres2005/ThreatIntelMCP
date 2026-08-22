import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from database.connection import engine
from semantic_search.embedding_service import EMBEDDING_MODEL_NAME
from topic_modeling.emerging_topic_service import detect_emerging_topics
from fastapi.testclient import TestClient

import mcp_server.server as mcp_server
from api.app import app

pytestmark = pytest.mark.integration


def _normalized_vector(first, second):
    magnitude = (first**2 + second**2) ** 0.5

    return [
        first / magnitude,
        second / magnitude,
        *([0.0] * 382),
    ]


def _insert_article_with_embedding(
    connection,
    *,
    title,
    published,
    embedding,
):
    article_id = connection.execute(
        text(
            """
            INSERT INTO articles (
                title,
                link,
                published,
                summary,
                processed,
                source
            )
            VALUES (
                :title,
                :link,
                :published,
                :summary,
                false,
                'controlled_topic_feed'
            )
            RETURNING id
            """
        ),
        {
            "title": title,
            "link": (
                "https://integration.test/topics/"
                + title.lower().replace(" ", "-")
            ),
            "published": published,
            "summary": (
                "Controlled ransomware campaign targeting "
                "enterprise infrastructure."
            ),
        },
    ).scalar_one()

    connection.execute(
        text(
            """
            INSERT INTO intelligence_embeddings (
                entity_type,
                entity_id,
                embedding,
                embedding_model,
                content_hash
            )
            VALUES (
                'article',
                :entity_id,
                CAST(:embedding AS vector),
                :embedding_model,
                :content_hash
            )
            """
        ),
        {
            "entity_id": str(article_id),
            "embedding": json.dumps(embedding),
            "embedding_model": EMBEDDING_MODEL_NAME,
            "content_hash": f"controlled-topic-{article_id}",
        },
    )

    return article_id

def test_detect_emerging_topics_uses_stored_postgresql_data():
    reference_time = datetime.now(timezone.utc)

    controlled_articles = [
        (
            "Acme ransomware campaign one",
            reference_time - timedelta(days=1),
            _normalized_vector(1.0, 0.01),
        ),
        (
            "Acme ransomware campaign two",
            reference_time - timedelta(days=2),
            _normalized_vector(1.0, 0.02),
        ),
        (
            "Acme ransomware campaign three",
            reference_time - timedelta(days=3),
            _normalized_vector(1.0, 0.03),
        ),
        (
            "Acme ransomware campaign previous",
            reference_time - timedelta(days=10),
            _normalized_vector(1.0, 0.04),
        ),
    ]

    with engine.begin() as connection:
        cluster_article_ids = [
            _insert_article_with_embedding(
                connection,
                title=title,
                published=published,
                embedding=embedding,
            )
            for title, published, embedding in controlled_articles
        ]

        noise_article_id = _insert_article_with_embedding(
            connection,
            title="Unrelated isolated security report",
            published=reference_time - timedelta(days=12),
            embedding=_normalized_vector(0.0, 1.0),
        )

        connection.execute(
            text(
                """
                INSERT INTO article_analysis (
                    article_id,
                    summary,
                    classification,
                    severity,
                    confidence_score,
                    cves
                )
                VALUES (
                    :article_id,
                    :summary,
                    CAST(:classification AS jsonb),
                    'High',
                    0.91,
                    CAST(:cves AS jsonb)
                )
                """
            ),
            {
                "article_id": cluster_article_ids[0],
                "summary": (
                    "Acme ransomware activity exploiting "
                    "a controlled vulnerability."
                ),
                "classification": json.dumps(["ransomware"]),
                "cves": json.dumps(["CVE-2026-90001"]),
            },
        )

    result = detect_emerging_topics(
        observation_days=30,
        recent_days=7,
        limit=10,
        reference_time=reference_time,
    )

    assert result["considered_article_count"] == 5
    assert result["clustered_article_count"] == 4
    assert result["noise_article_count"] == 1
    assert len(result["topics"]) == 1

    topic = result["topics"][0]

    assert topic["article_count"] == 4
    assert topic["recent_article_count"] == 3
    assert topic["previous_article_count"] == 1
    assert topic["recent_share"] == pytest.approx(1.0)
    assert topic["previous_share"] == pytest.approx(0.5)
    assert topic["trend"] == "rising"
    assert topic["trend_score"] == pytest.approx(0.5)

    assert topic["sources"] == ["controlled_topic_feed"]
    assert "ransomware" in topic["classifications"]
    assert "CVE-2026-90001" in topic["cves"]

    representative_ids = {
        article["article_id"]
        for article in topic["representative_articles"]
    }

    assert representative_ids.issubset(
        set(cluster_article_ids)
    )
    assert noise_article_id not in representative_ids

def test_rest_and_mcp_return_consistent_emerging_topics():
    reference_time = datetime.now(timezone.utc)

    article_definitions = [
        (
            "Controlled cloud ransomware one",
            reference_time - timedelta(days=1),
            _normalized_vector(1.0, 0.01),
        ),
        (
            "Controlled cloud ransomware two",
            reference_time - timedelta(days=2),
            _normalized_vector(1.0, 0.02),
        ),
        (
            "Controlled cloud ransomware three",
            reference_time - timedelta(days=3),
            _normalized_vector(1.0, 0.03),
        ),
        (
            "Controlled cloud ransomware previous",
            reference_time - timedelta(days=10),
            _normalized_vector(1.0, 0.04),
        ),
        (
            "Isolated authentication report",
            reference_time - timedelta(days=12),
            _normalized_vector(0.0, 1.0),
        ),
    ]

    with engine.begin() as connection:
        article_ids = [
            _insert_article_with_embedding(
                connection,
                title=title,
                published=published,
                embedding=embedding,
            )
            for title, published, embedding in article_definitions
        ]

    parameters = {
        "observation_days": 30,
        "recent_days": 7,
        "limit": 10,
    }

    with TestClient(app) as client:
        rest_response = client.get(
            "/api/v1/topics/emerging",
            params=parameters,
        )

    mcp_result = mcp_server.get_emerging_threat_topics(
        **parameters,
    )

    assert rest_response.status_code == 200

    rest_result = rest_response.json()

    for field in (
        "observation_days",
        "recent_days",
        "limit",
        "considered_article_count",
        "clustered_article_count",
        "noise_article_count",
    ):
        assert rest_result[field] == mcp_result[field]

    assert len(rest_result["topics"]) == 1
    assert len(mcp_result["topics"]) == 1

    rest_topic = rest_result["topics"][0]
    mcp_topic = mcp_result["topics"][0]

    for field in (
        "label",
        "keywords",
        "article_count",
        "recent_article_count",
        "previous_article_count",
        "recent_share",
        "previous_share",
        "trend",
        "trend_score",
        "sources",
        "classifications",
        "cves",
    ):
        assert rest_topic[field] == mcp_topic[field]

    rest_representative_ids = [
        article["article_id"]
        for article in rest_topic["representative_articles"]
    ]
    mcp_representative_ids = [
        article["article_id"]
        for article in mcp_topic["representative_articles"]
    ]

    assert rest_representative_ids == mcp_representative_ids
    assert set(rest_representative_ids).issubset(
        set(article_ids[:4])
    )
    assert article_ids[4] not in rest_representative_ids
