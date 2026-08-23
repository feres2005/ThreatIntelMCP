from types import SimpleNamespace
from unittest.mock import MagicMock
from datetime import datetime, timezone
import pytest

from database import (
    github_advisory_repository as repository,
)


def test_search_includes_packages_and_ecosystem(
    monkeypatch,
):
    row = SimpleNamespace(
        ghsa_id="GHSA-v667-gc2r-2xm7",
        cve_id="CVE-2026-55445",
        summary="Improper authentication.",
        severity="critical",
        published_at=None,
        updated_at=None,
        cvss_v3_score=None,
        cvss_v4_score=9.3,
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

    result = repository.search_github_advisories(
        "@whyour/qinglong",
        severity="critical",
        ecosystem="npm",
    )

    assert result[0]["ghsa_id"] == (
        "GHSA-v667-gc2r-2xm7"
    )

    query = connection.execute.call_args.args[0]
    parameters = (
        connection.execute.call_args.args[1]
    )
    normalized_sql = " ".join(
        str(query).split()
    )

    assert (
        "github_advisories.description "
        "ILIKE :keyword"
        in normalized_sql
    )
    assert (
        "keyword_vulnerability.package_name "
        "ILIKE :keyword"
        in normalized_sql
    )
    assert (
        "ecosystem_vulnerability.ecosystem "
        "= :ecosystem"
        in normalized_sql
    )
    assert parameters["ecosystem"] == "npm"
    assert parameters["severity"] == "critical"


@pytest.mark.parametrize(
    "ecosystem",
    [
        "",
        "unknown",
        123,
    ],
)
def test_search_rejects_invalid_ecosystem(
    ecosystem,
):
    with pytest.raises(ValueError):
        repository.search_github_advisories(
            "package",
            ecosystem=ecosystem,
        )

def test_supporting_articles_return_cve_evidence(
    monkeypatch,
):
    published = datetime(
        2026,
        8,
        20,
        12,
        0,
        tzinfo=timezone.utc,
    )

    advisory_result = MagicMock()
    advisory_result.fetchone.return_value = (
        SimpleNamespace(
            cve_id="CVE-2026-55445",
        )
    )

    article_result = MagicMock()
    article_result.fetchall.return_value = [
        SimpleNamespace(
            article_id=13310,
            title="Critical vulnerability",
            link="https://example.com/article",
            source="the_hacker_news",
            published=published,
            severity="Critical",
            confidence_score=0.92,
            supporting_article_count=1,
        )
    ]

    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.execute.side_effect = [
        advisory_result,
        article_result,
    ]

    fake_engine = MagicMock()
    fake_engine.connect.return_value = connection

    monkeypatch.setattr(
        repository,
        "engine",
        fake_engine,
    )

    result = (
        repository
        .get_github_advisory_supporting_articles(
            "GHSA-V667-GC2R-2XM7",
            limit=5,
        )
    )

    assert result["ghsa_id"] == (
        "GHSA-v667-gc2r-2xm7"
    )
    assert result["cve_id"] == (
        "CVE-2026-55445"
    )
    assert (
        result["supporting_article_count"]
        == 1
    )
    assert result["returned_count"] == 1
    assert result["articles"][0][
        "article_id"
    ] == 13310

    article_query = (
        connection.execute.call_args_list[1]
        .args[0]
    )
    normalized_sql = " ".join(
        str(article_query).split()
    )

    assert (
        "jsonb_typeof( "
        "article_analysis.cves "
        ") = 'array'"
        in normalized_sql
    )
    assert (
        "jsonb_array_elements_text( "
        "article_analysis.cves "
        ") AS cve_value"
        in normalized_sql
    )


def test_supporting_articles_handle_no_cve(
    monkeypatch,
):
    advisory_result = MagicMock()
    advisory_result.fetchone.return_value = (
        SimpleNamespace(cve_id=None)
    )

    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.execute.return_value = (
        advisory_result
    )

    fake_engine = MagicMock()
    fake_engine.connect.return_value = connection

    monkeypatch.setattr(
        repository,
        "engine",
        fake_engine,
    )

    result = (
        repository
        .get_github_advisory_supporting_articles(
            "GHSA-v667-gc2r-2xm7"
        )
    )

    assert result["cve_id"] is None
    assert result["supporting_article_count"] == 0
    assert result["returned_count"] == 0
    assert result["articles"] == []
    assert connection.execute.call_count == 1


def test_supporting_articles_return_none_when_missing(
    monkeypatch,
):
    advisory_result = MagicMock()
    advisory_result.fetchone.return_value = None

    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.execute.return_value = (
        advisory_result
    )

    fake_engine = MagicMock()
    fake_engine.connect.return_value = connection

    monkeypatch.setattr(
        repository,
        "engine",
        fake_engine,
    )

    result = (
        repository
        .get_github_advisory_supporting_articles(
            "GHSA-9999-9999-9999"
        )
    )

    assert result is None