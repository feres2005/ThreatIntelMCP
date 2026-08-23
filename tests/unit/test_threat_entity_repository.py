from datetime import (
    datetime,
    timezone,
)
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import database.threat_entity_repository as repository


def create_fake_engine(rows):
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.execute.return_value.fetchall.return_value = (
        rows
    )

    fake_engine = MagicMock()
    fake_engine.connect.return_value = connection

    return fake_engine, connection


def test_search_threat_entities_groups_values_safely(
    monkeypatch,
):
    latest_seen = datetime(
        2026,
        8,
        22,
        12,
        30,
        tzinfo=timezone.utc,
    )

    row = SimpleNamespace(
        value="Government",
        supporting_article_count=22,
        latest_seen=latest_seen,
    )

    fake_engine, connection = create_fake_engine(
        [row]
    )

    monkeypatch.setattr(
        repository,
        "engine",
        fake_engine,
    )

    result = (
        repository.search_threat_entity_values(
            "targeted_sector",
            "  govern  ",
            limit=5,
            offset=2,
        )
    )

    assert result == {
        "entity_type": "targeted_sector",
        "keyword": "govern",
        "limit": 5,
        "offset": 2,
        "returned_count": 1,
        "results": [
            {
                "value": "Government",
                "supporting_article_count": 22,
                "latest_seen": (
                    "2026-08-22T12:30:00+00:00"
                ),
            }
        ],
    }

    query = connection.execute.call_args.args[0]
    parameters = (
        connection.execute.call_args.args[1]
    )
    normalized_sql = " ".join(
        str(query).split()
    )

    assert (
        "jsonb_typeof( "
        "article_analysis.targeted_sectors "
        ") = 'array'"
        in normalized_sql
    )
    assert (
        "GROUP BY LOWER(entity_value)"
        in normalized_sql
    )
    assert parameters == {
        "keyword": "%govern%",
        "limit": 5,
        "offset": 2,
    }


def test_get_threat_entity_evidence_returns_articles(
    monkeypatch,
):
    published = datetime(
        2026,
        8,
        20,
        9,
        15,
        tzinfo=timezone.utc,
    )

    row = SimpleNamespace(
        article_id=13316,
        title="Government portal attack",
        link="https://example.com/article",
        source="the_hacker_news",
        published=published,
        summary="A threat campaign.",
        severity="High",
        confidence_score=Decimal("0.85"),
        cves=["CVE-2026-50522"],
        malware=["ExampleRAT"],
        mitre_techniques=["T1530"],
        apt_groups=["Example Group"],
        targeted_sectors=["Government"],
        affected_technologies=[
            "Microsoft 365",
        ],
        supporting_article_count=3,
    )

    fake_engine, connection = create_fake_engine(
        [row]
    )

    monkeypatch.setattr(
        repository,
        "engine",
        fake_engine,
    )

    result = (
        repository.get_threat_entity_evidence(
            "apt_group",
            "  Example Group  ",
            limit=12,
        )
    )

    assert result["entity_type"] == "apt_group"
    assert result["value"] == "Example Group"
    assert result["limit"] == 12
    assert (
        result["supporting_article_count"]
        == 3
    )
    assert result["returned_count"] == 1

    article = result["articles"][0]

    assert article == {
        "article_id": 13316,
        "title": "Government portal attack",
        "link": "https://example.com/article",
        "source": "the_hacker_news",
        "published": (
            "2026-08-20T09:15:00+00:00"
        ),
        "summary": "A threat campaign.",
        "severity": "High",
        "confidence_score": 0.85,
        "cves": ["CVE-2026-50522"],
        "malware": ["ExampleRAT"],
        "mitre_techniques": ["T1530"],
        "apt_groups": ["Example Group"],
        "targeted_sectors": ["Government"],
        "affected_technologies": [
            "Microsoft 365",
        ],
    }

    query = connection.execute.call_args.args[0]
    parameters = (
        connection.execute.call_args.args[1]
    )
    normalized_sql = " ".join(
        str(query).split()
    )

    assert (
        "jsonb_typeof( "
        "article_analysis.apt_groups "
        ") = 'array'"
        in normalized_sql
    )
    assert (
        "LOWER(entity_value) = LOWER(:value)"
        in normalized_sql
    )
    assert parameters == {
        "value": "Example Group",
        "limit": 12,
    }


def test_get_threat_entity_evidence_handles_no_articles(
    monkeypatch,
):
    fake_engine, _ = create_fake_engine([])

    monkeypatch.setattr(
        repository,
        "engine",
        fake_engine,
    )

    result = (
        repository.get_threat_entity_evidence(
            "malware",
            "UnknownMalware",
        )
    )

    assert result[
        "supporting_article_count"
    ] == 0
    assert result["returned_count"] == 0
    assert result["articles"] == []


@pytest.mark.parametrize(
    "entity_type",
    [
        None,
        "",
        "mitre",
        "unknown",
    ],
)
def test_entity_search_rejects_invalid_type(
    entity_type,
):
    with pytest.raises(ValueError):
        repository.search_threat_entity_values(
            entity_type,
            "test",
        )


@pytest.mark.parametrize(
    (
        "keyword",
        "limit",
        "offset",
    ),
    [
        ("", 10, 0),
        ("   ", 10, 0),
        ("test", 0, 0),
        ("test", 51, 0),
        ("test", True, 0),
        ("test", 10, -1),
        ("test", 10, True),
    ],
)
def test_entity_search_rejects_invalid_parameters(
    keyword,
    limit,
    offset,
):
    with pytest.raises(ValueError):
        repository.search_threat_entity_values(
            "malware",
            keyword,
            limit=limit,
            offset=offset,
        )