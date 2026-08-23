from datetime import datetime, timezone
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import database.cve_repository as repository


pytestmark = pytest.mark.unit


def test_get_cve_supporting_articles_returns_evidence(
    monkeypatch,
):
    published = datetime(
        2026,
        8,
        20,
        14,
        30,
        tzinfo=timezone.utc,
    )

    row = SimpleNamespace(
        article_id=501,
        title="Critical package vulnerability",
        link="https://example.com/article-501",
        published=published,
        severity="Critical",
        confidence_score=Decimal("0.91"),
        supporting_article_count=2,
        source="example_feed",
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

    result = repository.get_cve_supporting_articles(
        "  cve-2026-50522  ",
        limit=1,
    )

    assert result == {
        "cve_id": "CVE-2026-50522",
        "supporting_article_count": 2,
        "articles": [
            {
                "article_id": 501,
                "title": (
                    "Critical package vulnerability"
                ),
                "link": (
                    "https://example.com/article-501"
                ),
                "source": "example_feed",
                "published": published.isoformat(),
                "severity": "Critical",
                "confidence_score": 0.91,
            },
        ],
    }

    fake_engine.connect.assert_called_once_with()
    connection.execute.assert_called_once()

    query, parameters = (
        connection.execute.call_args.args
    )
    normalized_sql = " ".join(
        str(query).split()
    )

    assert (
        "COUNT(*) OVER() "
        "AS supporting_article_count"
        in normalized_sql
    )
    assert (
        "jsonb_typeof(article_analysis.cves) "
        "= 'array'"
        in normalized_sql
    )
    assert (
        "UPPER(cve_value) = :cve_id"
        in normalized_sql
    )
    assert (
        "ORDER BY articles.published DESC "
        "NULLS LAST"
        in normalized_sql
    )

    assert parameters == {
        "cve_id": "CVE-2026-50522",
        "limit": 1,
    }

def test_get_cve_supporting_articles_returns_empty_result(
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

    result = repository.get_cve_supporting_articles(
        "CVE-2026-50522",
        limit=20,
    )

    assert result == {
        "cve_id": "CVE-2026-50522",
        "supporting_article_count": 0,
        "articles": [],
    }


@pytest.mark.parametrize(
    (
        "cve_id",
        "limit",
        "expected_message",
    ),
    [
        (
            None,
            20,
            "CVE ID must be a string.",
        ),
        (
            "not-a-cve",
            20,
            (
                "CVE ID must follow the format "
                "CVE-YYYY-NNNN."
            ),
        ),
        (
            "CVE-2026-50522",
            0,
            (
                "Supporting article limit must be "
                "between 1 and 50."
            ),
        ),
        (
            "CVE-2026-50522",
            51,
            (
                "Supporting article limit must be "
                "between 1 and 50."
            ),
        ),
        (
            "CVE-2026-50522",
            True,
            (
                "Supporting article limit must be "
                "between 1 and 50."
            ),
        ),
    ],
)
def test_get_cve_supporting_articles_rejects_invalid_input(
    monkeypatch,
    cve_id,
    limit,
    expected_message,
):
    fake_engine = MagicMock()

    monkeypatch.setattr(
        repository,
        "engine",
        fake_engine,
    )

    with pytest.raises(ValueError) as error_info:
        repository.get_cve_supporting_articles(
            cve_id,
            limit=limit,
        )

    assert str(error_info.value) == (
        expected_message
    )
    fake_engine.connect.assert_not_called()