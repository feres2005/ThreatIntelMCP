from datetime import datetime, timezone
from unittest.mock import MagicMock
import pytest
from decimal import Decimal
from types import SimpleNamespace
import database.embedding_repository as repository


pytestmark = pytest.mark.unit


VALID_PUBLISHED_AFTER = datetime(
    2026,
    7,
    23,
    tzinfo=timezone.utc,
)


@pytest.mark.parametrize(
    (
        "arguments",
        "expected_message",
    ),
    [
        (
            {
                "published_after": None,
                "embedding_model": "test-model",
                "limit": 100,
            },
            "Published-after time must be timezone-aware.",
        ),
        (
            {
                "published_after": datetime(
                    2026,
                    7,
                    23,
                ),
                "embedding_model": "test-model",
                "limit": 100,
            },
            "Published-after time must be timezone-aware.",
        ),
        (
            {
                "published_after": VALID_PUBLISHED_AFTER,
                "embedding_model": None,
                "limit": 100,
            },
            "Embedding model must be a non-empty string.",
        ),
        (
            {
                "published_after": VALID_PUBLISHED_AFTER,
                "embedding_model": "   ",
                "limit": 100,
            },
            "Embedding model must be a non-empty string.",
        ),
        (
            {
                "published_after": VALID_PUBLISHED_AFTER,
                "embedding_model": "test-model",
                "limit": 0,
            },
            "Limit must be between 1 and 500.",
        ),
        (
            {
                "published_after": VALID_PUBLISHED_AFTER,
                "embedding_model": "test-model",
                "limit": 501,
            },
            "Limit must be between 1 and 500.",
        ),
        (
            {
                "published_after": VALID_PUBLISHED_AFTER,
                "embedding_model": "test-model",
                "limit": True,
            },
            "Limit must be between 1 and 500.",
        ),
    ],
)
def test_get_topic_modeling_articles_rejects_invalid_parameters(
    arguments,
    expected_message,
):
    with pytest.raises(ValueError) as error_info:
        repository.get_topic_modeling_articles(
            **arguments,
        )

    assert str(error_info.value) == expected_message

def test_get_topic_modeling_articles_queries_expected_window(
    monkeypatch,
):
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.execute.return_value.fetchall.return_value = []

    fake_engine = MagicMock()
    fake_engine.connect.return_value = connection

    monkeypatch.setattr(
        repository,
        "engine",
        fake_engine,
    )

    result = repository.get_topic_modeling_articles(
        published_after=VALID_PUBLISHED_AFTER,
        embedding_model="  test-model  ",
        limit=100,
    )

    assert result == []

    fake_engine.connect.assert_called_once_with()
    connection.execute.assert_called_once()

    query, parameters = (
        connection.execute.call_args.args
    )
    normalized_sql = " ".join(
        str(query).split()
    )

    assert (
        "articles.published >= :published_after"
        in normalized_sql
    )
    assert (
        "intelligence_embeddings.embedding_model "
        "= :embedding_model"
        in normalized_sql
    )
    assert (
        "ORDER BY articles.published DESC"
        in normalized_sql
    )
    assert "LIMIT :limit" in normalized_sql

    assert parameters == {
        "published_after": VALID_PUBLISHED_AFTER,
        "embedding_model": "test-model",
        "limit": 100,
    }
def test_get_topic_modeling_articles_normalizes_rows(
    monkeypatch,
):
    embedding = [
        index / 1000
        for index in range(384)
    ]
    embedding_text = (
        "["
        + ",".join(str(value) for value in embedding)
        + "]"
    )
    published = datetime(
        2026,
        8,
        21,
        18,
        30,
        tzinfo=timezone.utc,
    )

    row = SimpleNamespace(
        article_id=701,
        title="Ransomware targets hospitals",
        link="https://example.com/article-701",
        source="test_feed",
        published=published,
        summary="A coordinated ransomware campaign.",
        classification=["ransomware"],
        severity="High",
        confidence_score=Decimal("0.87"),
        cves=["CVE-2026-12345"],
        malware=["ExampleLock"],
        mitre_techniques=["T1486"],
        apt_groups=["Example Group"],
        targeted_sectors=["Healthcare"],
        affected_technologies=["Windows"],
        embedding_text=embedding_text,
    )

    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.execute.return_value.fetchall.return_value = [
        row,
    ]

    fake_engine = MagicMock()
    fake_engine.connect.return_value = connection

    monkeypatch.setattr(
        repository,
        "engine",
        fake_engine,
    )

    result = repository.get_topic_modeling_articles(
        published_after=VALID_PUBLISHED_AFTER,
        embedding_model="test-model",
        limit=100,
    )

    assert result == [
        {
            "article_id": 701,
            "title": "Ransomware targets hospitals",
            "link": "https://example.com/article-701",
            "source": "test_feed",
            "published": published,
            "summary": (
                "A coordinated ransomware campaign."
            ),
            "classification": ["ransomware"],
            "severity": "High",
            "confidence_score": 0.87,
            "cves": ["CVE-2026-12345"],
            "malware": ["ExampleLock"],
            "mitre_techniques": ["T1486"],
            "apt_groups": ["Example Group"],
            "targeted_sectors": ["Healthcare"],
            "affected_technologies": ["Windows"],
            "embedding": embedding,
        },
    ]
@pytest.mark.parametrize(
    "stored_embedding",
    [
        "not-valid-json",
        "{}",
        "[0.0]",
        (
            "["
            + ",".join(
                ["0.0"] * 383
                + ["true"]
            )
            + "]"
        ),
        (
            "["
            + ",".join(
                ["0.0"] * 383
                + ['"invalid"']
            )
            + "]"
        ),
        (
            "["
            + ",".join(
                ["0.0"] * 383
                + ["NaN"]
            )
            + "]"
        ),
    ],
)
def test_deserialize_stored_embedding_rejects_corruption(
    stored_embedding,
):
    with pytest.raises(ValueError) as error_info:
        repository._deserialize_stored_embedding(
            stored_embedding,
        )

    assert str(error_info.value) == (
        "Stored embedding must contain exactly "
        "384 finite numbers."
    )
