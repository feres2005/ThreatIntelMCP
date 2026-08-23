from datetime import datetime, timezone
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import database.mitre_repository as repository


pytestmark = pytest.mark.unit


def test_search_mitre_includes_description_and_platforms(
    monkeypatch,
):
    row = SimpleNamespace(
        _mapping={
            "technique_id": "T1059.001",
            "name": "PowerShell",
            "domain": "enterprise-attack",
            "is_subtechnique": True,
            "version": "1.5",
            "revoked": False,
            "deprecated": False,
        }
    )

    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.execute.return_value = [row]

    fake_engine = MagicMock()
    fake_engine.connect.return_value = connection

    monkeypatch.setattr(
        repository,
        "engine",
        fake_engine,
    )

    result = repository.search_mitre_techniques(
        "  Windows  ",
        domain="enterprise-attack",
    )

    assert result == [dict(row._mapping)]

    query, parameters = (
        connection.execute.call_args.args
    )

    normalized_sql = " ".join(
        str(query).split()
    )

    assert (
        "description ILIKE :keyword"
        in normalized_sql
    )
    assert (
        "jsonb_typeof(platforms) = 'array'"
        in normalized_sql
    )
    assert (
        "platform_name ILIKE :keyword"
        in normalized_sql
    )

    assert parameters == {
        "keyword": "%Windows%",
        "limit": 10,
        "offset": 0,
        "domain": "enterprise-attack",
        "include_inactive": False,
    }


def test_get_mitre_supporting_articles_returns_evidence(
    monkeypatch,
):
    published = datetime(
        2026,
        8,
        20,
        12,
        30,
        tzinfo=timezone.utc,
    )

    row = SimpleNamespace(
        article_id=13310,
        title="Technique observed in campaign",
        link="https://example.com/article-13310",
        source="the_hacker_news",
        published=published,
        severity="High",
        confidence_score=Decimal("0.85"),
        supporting_article_count=3,
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

    result = (
        repository.get_mitre_supporting_articles(
            "  t1530  ",
            limit=5,
        )
    )

    assert result == {
        "technique_id": "T1530",
        "supporting_article_count": 3,
        "articles": [
            {
                "article_id": 13310,
                "title": (
                    "Technique observed in campaign"
                ),
                "link": (
                    "https://example.com/"
                    "article-13310"
                ),
                "source": "the_hacker_news",
                "published": published.isoformat(),
                "severity": "High",
                "confidence_score": 0.85,
            }
        ],
    }

    query, parameters = (
        connection.execute.call_args.args
    )

    normalized_sql = " ".join(
        str(query).split()
    )

    assert (
        "jsonb_typeof( "
        "article_analysis.mitre_techniques "
        ") = 'array'"
        in normalized_sql
    )
    assert (
        "UPPER(technique_value) "
        "= :technique_id"
        in normalized_sql
    )
    assert (
        "COUNT(*) OVER() "
        "AS supporting_article_count"
        in normalized_sql
    )

    assert parameters == {
        "technique_id": "T1530",
        "limit": 5,
    }


def test_get_mitre_supporting_articles_handles_no_evidence(
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

    result = (
        repository.get_mitre_supporting_articles(
            "T1566.002"
        )
    )

    assert result == {
        "technique_id": "T1566.002",
        "supporting_article_count": 0,
        "articles": [],
    }


@pytest.mark.parametrize(
    "technique_id",
    [
        None,
        "",
        "T123",
        "T12345",
        "T1566.02",
        "not-a-technique",
    ],
)
def test_get_mitre_supporting_articles_rejects_invalid_id(
    technique_id,
):
    with pytest.raises(ValueError):
        repository.get_mitre_supporting_articles(
            technique_id
        )


@pytest.mark.parametrize(
    "limit",
    [
        0,
        51,
        True,
        1.5,
    ],
)
def test_get_mitre_supporting_articles_rejects_invalid_limit(
    limit,
):
    with pytest.raises(ValueError):
        repository.get_mitre_supporting_articles(
            "T1530",
            limit=limit,
        )