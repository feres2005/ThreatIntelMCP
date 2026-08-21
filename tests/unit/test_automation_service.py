from types import SimpleNamespace

import pytest

import pipeline.automation_service as service
from pipeline.automation_service import (
    _calculate_percentage,
    get_pipeline_status,
    index_pending_embeddings,
    process_pending_articles,
    synchronize_github_intelligence,
    synchronize_mitre_intelligence,
)


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    (
        "value",
        "total",
        "expected",
    ),
    [
        (0, 0, 0.0),
        (10, 0, 0.0),
        (1, 4, 25.0),
        (2, 3, 66.67),
    ],
)
def test_calculate_percentage(
    value,
    total,
    expected,
):
    assert _calculate_percentage(
        value,
        total,
    ) == expected


@pytest.mark.parametrize(
    "limit",
    [
        None,
        0,
        -1,
        True,
        "5",
        5.0,
    ],
)
def test_process_pending_articles_rejects_invalid_limits(
    limit,
):
    with pytest.raises(ValueError) as error_info:
        process_pending_articles(limit)

    assert str(error_info.value) == (
        "Processing limit must be a "
        "positive integer."
    )


def test_process_pending_articles_rejects_large_limit():
    with pytest.raises(ValueError) as error_info:
        process_pending_articles(21)

    assert str(error_info.value) == (
        "Processing limit cannot exceed 20."
    )


@pytest.mark.parametrize(
    (
        "arguments",
        "expected_message",
    ),
    [
        (
            {
                "include_otx": 1,
            },
            "include_otx must be a boolean.",
        ),
        (
            {
                "include_cve": "false",
            },
            "include_cve must be a boolean.",
        ),
    ],
)
def test_process_pending_articles_rejects_invalid_flags(
    arguments,
    expected_message,
):
    with pytest.raises(ValueError) as error_info:
        process_pending_articles(
            5,
            **arguments
        )

    assert str(error_info.value) == (
        expected_message
    )


def test_process_pending_articles_delegates_selected_ids(
    monkeypatch,
):
    captured = {}

    pending_articles = [
        SimpleNamespace(
            id=101,
            title="First",
        ),
        SimpleNamespace(
            id=102,
            title="Second",
        ),
    ]

    batch_result = {
        "selection_mode": "unprocessed_only",
        "selected_article_count": 2,
        "successful_count": 2,
        "unsuccessful_count": 0,
        "results": [],
    }

    def fake_get_unprocessed(limit):
        captured["repository_limit"] = limit
        return pending_articles

    def fake_process_batch(
        article_ids,
        *,
        limit,
        include_otx,
        include_cve,
        reanalyze,
    ):
        captured["batch_arguments"] = {
            "article_ids": article_ids,
            "limit": limit,
            "include_otx": include_otx,
            "include_cve": include_cve,
            "reanalyze": reanalyze,
        }
        return batch_result

    monkeypatch.setattr(
        service,
        "get_unprocessed_articles",
        fake_get_unprocessed,
    )
    monkeypatch.setattr(
        service,
        "process_article_batch",
        fake_process_batch,
    )

    result = process_pending_articles(
        2,
        include_otx=True,
        include_cve=True,
    )

    assert captured["repository_limit"] == 2
    assert captured["batch_arguments"] == {
        "article_ids": [
            101,
            102,
        ],
        "limit": 2,
        "include_otx": True,
        "include_cve": True,
        "reanalyze": False,
    }

    assert result == {
        "operation": "process_pending_articles",
        "requested_limit": 2,
        "selected_article_ids": [
            101,
            102,
        ],
        **batch_result,
    }


def test_process_pending_articles_handles_empty_queue(
    monkeypatch,
):
    captured = {}

    monkeypatch.setattr(
        service,
        "get_unprocessed_articles",
        lambda limit: [],
    )

    def fake_process_batch(
        article_ids,
        **arguments,
    ):
        captured["article_ids"] = article_ids
        return {
            "selected_article_count": 0,
            "successful_count": 0,
            "unsuccessful_count": 0,
            "results": [],
        }

    monkeypatch.setattr(
        service,
        "process_article_batch",
        fake_process_batch,
    )

    result = process_pending_articles(5)

    assert captured["article_ids"] == []
    assert result["selected_article_ids"] == []
    assert result["successful_count"] == 0


@pytest.mark.parametrize(
    "limit",
    [
        None,
        0,
        -1,
        True,
        "25",
        25.0,
    ],
)
def test_index_pending_embeddings_rejects_invalid_limits(
    limit,
):
    with pytest.raises(ValueError) as error_info:
        index_pending_embeddings(limit)

    assert str(error_info.value) == (
        "Embedding limit must be a positive "
        "integer."
    )


def test_index_pending_embeddings_rejects_large_limit():
    with pytest.raises(ValueError) as error_info:
        index_pending_embeddings(101)

    assert str(error_info.value) == (
        "Embedding limit cannot exceed 100."
    )


def test_index_pending_embeddings_handles_empty_queue(
    monkeypatch,
):
    monkeypatch.setattr(
        service,
        "index_missing_articles",
        lambda limit: [],
    )

    assert index_pending_embeddings(25) == {
        "operation": "index_pending_embeddings",
        "requested_limit": 25,
        "selected_count": 0,
        "successful_count": 0,
        "unsuccessful_count": 0,
        "status_counts": {},
        "results": [],
    }


def test_index_pending_embeddings_aggregates_statuses(
    monkeypatch,
):
    results = [
        {
            "article_id": 1,
            "status": "created",
        },
        {
            "article_id": 2,
            "status": "updated",
        },
        {
            "article_id": 3,
            "status": "unchanged",
        },
        {
            "article_id": 4,
            "status": "failed",
        },
        {
            "article_id": 5,
            "status": "created",
        },
    ]

    captured = {}

    def fake_index_missing(limit):
        captured["limit"] = limit
        return results

    monkeypatch.setattr(
        service,
        "index_missing_articles",
        fake_index_missing,
    )

    result = index_pending_embeddings(5)

    assert captured["limit"] == 5
    assert result == {
        "operation": "index_pending_embeddings",
        "requested_limit": 5,
        "selected_count": 5,
        "successful_count": 4,
        "unsuccessful_count": 1,
        "status_counts": {
            "created": 2,
            "updated": 1,
            "unchanged": 1,
            "failed": 1,
        },
        "results": results,
    }


def _build_status_counts(**overrides):
    counts = {
        "total_articles": 10,
        "processed_articles": 4,
        "pending_articles": 6,
        "analyzed_articles": 3,
        "processed_without_analysis": 0,
        "pending_with_analysis": 0,
        "typed_ioc_rows": 2,
        "articles_with_typed_iocs": 1,
        "article_embeddings": 8,
        "articles_missing_embeddings": 2,
        "enriched_cves": 1,
        "cached_otx_indicators": 3,
        "mitre_techniques": 100,
        "github_advisories": 200,
    }
    counts.update(overrides)
    return counts


def test_get_pipeline_status_returns_healthy_coverage(
    monkeypatch,
):
    counts = _build_status_counts()

    monkeypatch.setattr(
        service,
        "get_pipeline_status_counts",
        lambda: counts,
    )

    result = get_pipeline_status()

    assert result == {
        "operation": "get_pipeline_status",
        "health_status": "healthy",
        "work_pending": {
            "article_processing": 6,
            "embedding_indexing": 2,
        },
        "coverage": {
            "processing_percent": 40.0,
            "analysis_percent": 30.0,
            "embedding_percent": 80.0,
        },
        "counts": counts,
        "warnings": [],
    }


def test_get_pipeline_status_handles_empty_database(
    monkeypatch,
):
    counts = _build_status_counts(
        total_articles=0,
        processed_articles=0,
        pending_articles=0,
        analyzed_articles=0,
        article_embeddings=0,
        articles_missing_embeddings=0,
        typed_ioc_rows=0,
        articles_with_typed_iocs=0,
        enriched_cves=0,
        cached_otx_indicators=0,
        mitre_techniques=0,
        github_advisories=0,
    )

    monkeypatch.setattr(
        service,
        "get_pipeline_status_counts",
        lambda: counts,
    )

    result = get_pipeline_status()

    assert result["health_status"] == "healthy"
    assert result["coverage"] == {
        "processing_percent": 0.0,
        "analysis_percent": 0.0,
        "embedding_percent": 0.0,
    }


def test_get_pipeline_status_reports_consistency_warnings(
    monkeypatch,
):
    counts = _build_status_counts(
        processed_without_analysis=2,
        pending_with_analysis=3,
    )

    monkeypatch.setattr(
        service,
        "get_pipeline_status_counts",
        lambda: counts,
    )

    result = get_pipeline_status()

    assert result["health_status"] == (
        "attention_required"
    )
    assert result["warnings"] == [
        (
            "2 processed articles have no "
            "AI analysis."
        ),
        (
            "3 pending articles already have "
            "AI analysis."
        ),
    ]


@pytest.mark.parametrize(
    "domains",
    [
        "enterprise-attack",
        ("enterprise-attack",),
        123,
    ],
)
def test_synchronize_mitre_rejects_non_list_domains(
    domains,
):
    with pytest.raises(ValueError) as error_info:
        synchronize_mitre_intelligence(
            domains
        )

    assert str(error_info.value) == (
        "MITRE domains must be provided as "
        "a list."
    )


def test_synchronize_mitre_rejects_empty_domains():
    with pytest.raises(ValueError) as error_info:
        synchronize_mitre_intelligence([])

    assert str(error_info.value) == (
        "At least one MITRE domain is required."
    )


@pytest.mark.parametrize(
    "domain",
    [
        "unsupported",
        None,
        123,
    ],
)
def test_synchronize_mitre_rejects_unsupported_domains(
    domain,
):
    with pytest.raises(ValueError) as error_info:
        synchronize_mitre_intelligence([
            domain,
        ])

    assert str(error_info.value) == (
        "Unsupported MITRE domain: "
        f"{domain!r}."
    )


def test_synchronize_mitre_defaults_to_all_domains(
    monkeypatch,
):
    calls = []

    saved_counts = {
        "enterprise-attack": 858,
        "mobile-attack": 176,
        "ics-attack": 106,
    }

    def fake_collect(domain):
        calls.append(domain)
        return saved_counts[domain]

    monkeypatch.setattr(
        service,
        "collect_mitre_techniques",
        fake_collect,
    )

    result = synchronize_mitre_intelligence()

    assert calls == [
        "enterprise-attack",
        "mobile-attack",
        "ics-attack",
    ]
    assert result["status"] == "completed"
    assert result["successful_domain_count"] == 3
    assert result["failed_domain_count"] == 0
    assert result[
        "total_saved_techniques"
    ] == 1140


def test_synchronize_mitre_deduplicates_domains(
    monkeypatch,
):
    calls = []

    def fake_collect(domain):
        calls.append(domain)
        return 10

    monkeypatch.setattr(
        service,
        "collect_mitre_techniques",
        fake_collect,
    )

    result = synchronize_mitre_intelligence([
        "enterprise-attack",
        "enterprise-attack",
        "ics-attack",
    ])

    assert calls == [
        "enterprise-attack",
        "ics-attack",
    ]
    assert result["requested_domains"] == [
        "enterprise-attack",
        "ics-attack",
    ]
    assert result[
        "total_saved_techniques"
    ] == 20


def test_synchronize_mitre_isolates_domain_failure(
    monkeypatch,
):
    calls = []

    def fake_collect(domain):
        calls.append(domain)

        if domain == "mobile-attack":
            raise RuntimeError(
                "Simulated mobile failure"
            )

        return {
            "enterprise-attack": 858,
            "ics-attack": 106,
        }[domain]

    monkeypatch.setattr(
        service,
        "collect_mitre_techniques",
        fake_collect,
    )

    result = synchronize_mitre_intelligence()

    assert calls == [
        "enterprise-attack",
        "mobile-attack",
        "ics-attack",
    ]
    assert result["status"] == (
        "completed_with_warnings"
    )
    assert result["successful_domain_count"] == 2
    assert result["failed_domain_count"] == 1
    assert result[
        "total_saved_techniques"
    ] == 964
    assert result["results"][1] == {
        "domain": "mobile-attack",
        "status": "failed",
        "saved_technique_count": 0,
        "error": (
            "RuntimeError: "
            "Simulated mobile failure"
        ),
    }


def test_synchronize_mitre_fails_when_all_domains_fail(
    monkeypatch,
):
    def failing_collect(domain):
        raise RuntimeError(
            f"{domain} unavailable"
        )

    monkeypatch.setattr(
        service,
        "collect_mitre_techniques",
        failing_collect,
    )

    result = synchronize_mitre_intelligence([
        "enterprise-attack",
        "mobile-attack",
    ])

    assert result["status"] == "failed"
    assert result["successful_domain_count"] == 0
    assert result["failed_domain_count"] == 2
    assert result[
        "total_saved_techniques"
    ] == 0


def test_synchronize_github_intelligence_delegates(
    monkeypatch,
):
    expected = {
        "operation": (
            "synchronize_github_advisories"
        ),
        "status": "completed",
    }

    monkeypatch.setattr(
        service,
        "synchronize_all_github_advisories",
        lambda: expected,
    )

    assert synchronize_github_intelligence() is (
        expected
    )
