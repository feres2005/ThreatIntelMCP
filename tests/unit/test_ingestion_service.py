import pytest

import pipeline.ingestion_service as service
from pipeline.ingestion_service import (
    ingest_rss_articles,
)


pytestmark = pytest.mark.unit


def test_ingest_rss_articles_handles_empty_collection(
    monkeypatch,
):
    calls = {
        "count": 0,
    }

    def unexpected_insert(article):
        raise AssertionError(
            "No article should be inserted."
        )

    def fake_count_articles():
        calls["count"] += 1
        return 620

    monkeypatch.setattr(
        service,
        "collect_articles",
        lambda: [],
    )
    monkeypatch.setattr(
        service,
        "insert_article",
        unexpected_insert,
    )
    monkeypatch.setattr(
        service,
        "count_articles",
        fake_count_articles,
    )

    result = ingest_rss_articles()

    assert calls["count"] == 1
    assert result == {
        "operation": "rss_ingestion",
        "status": "completed",
        "collected_count": 0,
        "inserted_count": 0,
        "existing_or_updated_count": 0,
        "failed_count": 0,
        "inserted_article_ids": [],
        "existing_or_updated_article_ids": [],
        "failures": [],
        "database_article_count": 620,
    }


def test_ingest_rss_articles_tracks_existing_articles(
    monkeypatch,
):
    articles = [
        {
            "title": "Existing one",
            "link": "https://example.test/1",
        },
        {
            "title": "Existing two",
            "link": "https://example.test/2",
        },
    ]

    insert_results = iter([
        {
            "article_id": 101,
            "inserted": False,
        },
        {
            "article_id": 102,
            "inserted": False,
        },
    ])

    monkeypatch.setattr(
        service,
        "collect_articles",
        lambda: articles,
    )
    monkeypatch.setattr(
        service,
        "insert_article",
        lambda article: next(insert_results),
    )
    monkeypatch.setattr(
        service,
        "count_articles",
        lambda: 700,
    )

    result = ingest_rss_articles()

    assert result["status"] == "completed"
    assert result["collected_count"] == 2
    assert result["inserted_count"] == 0
    assert result[
        "existing_or_updated_count"
    ] == 2
    assert result[
        "existing_or_updated_article_ids"
    ] == [
        101,
        102,
    ]
    assert result["failed_count"] == 0


def test_ingest_rss_articles_isolates_insert_failures(
    monkeypatch,
):
    articles = [
        {
            "title": "New article",
            "link": "https://example.test/new",
        },
        {
            "title": "Existing article",
            "link": (
                "https://example.test/existing"
            ),
        },
        {
            "title": "Failed article",
            "link": "https://example.test/failed",
        },
        {
            "title": "Later article",
            "link": "https://example.test/later",
        },
    ]

    calls = []

    def fake_insert_article(article):
        calls.append(article["title"])

        if article["title"] == "New article":
            return {
                "article_id": 201,
                "inserted": True,
            }

        if article["title"] == (
            "Existing article"
        ):
            return {
                "article_id": 202,
                "inserted": False,
            }

        if article["title"] == (
            "Failed article"
        ):
            raise RuntimeError(
                "Simulated database failure"
            )

        return {
            "article_id": 204,
            "inserted": True,
        }

    monkeypatch.setattr(
        service,
        "collect_articles",
        lambda: articles,
    )
    monkeypatch.setattr(
        service,
        "insert_article",
        fake_insert_article,
    )
    monkeypatch.setattr(
        service,
        "count_articles",
        lambda: 704,
    )

    result = ingest_rss_articles()

    assert calls == [
        "New article",
        "Existing article",
        "Failed article",
        "Later article",
    ]

    assert result == {
        "operation": "rss_ingestion",
        "status": "completed_with_warnings",
        "collected_count": 4,
        "inserted_count": 2,
        "existing_or_updated_count": 1,
        "failed_count": 1,
        "inserted_article_ids": [
            201,
            204,
        ],
        "existing_or_updated_article_ids": [
            202,
        ],
        "failures": [
            {
                "position": 3,
                "title": "Failed article",
                "link": (
                    "https://example.test/failed"
                ),
                "error": (
                    "RuntimeError: Simulated "
                    "database failure"
                ),
            },
        ],
        "database_article_count": 704,
    }
