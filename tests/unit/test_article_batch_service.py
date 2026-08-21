from types import SimpleNamespace

import pytest

import pipeline.article_batch_service as service
from pipeline.article_batch_service import (
    process_article_batch,
)


pytestmark = pytest.mark.unit


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
def test_process_article_batch_rejects_invalid_limits(
    limit,
):
    with pytest.raises(ValueError) as error_info:
        process_article_batch(
            [],
            limit=limit,
        )

    assert str(error_info.value) == (
        "Batch limit must be a positive integer."
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
                "include_cve": "true",
            },
            "include_cve must be a boolean.",
        ),
        (
            {
                "reanalyze": 1,
            },
            "reanalyze must be a boolean.",
        ),
    ],
)
def test_process_article_batch_rejects_invalid_flags(
    arguments,
    expected_message,
):
    with pytest.raises(ValueError) as error_info:
        process_article_batch(
            [],
            **arguments
        )

    assert str(error_info.value) == (
        expected_message
    )


@pytest.mark.parametrize(
    "progress_callback",
    [
        123,
        "callback",
        [],
    ],
)
def test_process_article_batch_rejects_invalid_callback(
    progress_callback,
):
    with pytest.raises(ValueError) as error_info:
        process_article_batch(
            [],
            progress_callback=progress_callback,
        )

    assert str(error_info.value) == (
        "Progress callback must be callable "
        "or None."
    )


def test_process_article_batch_handles_empty_selection(
    monkeypatch,
):
    captured = {}

    def fake_get_unprocessed(article_ids):
        captured["article_ids"] = article_ids
        return []

    def unexpected_reanalysis(article_ids):
        raise AssertionError(
            "Reanalysis repository should not "
            "be called."
        )

    def unexpected_processing(
        article,
        **arguments,
    ):
        raise AssertionError(
            "No article should be processed."
        )

    monkeypatch.setattr(
        service,
        "get_unprocessed_articles_by_ids",
        fake_get_unprocessed,
    )
    monkeypatch.setattr(
        service,
        "get_articles_by_ids",
        unexpected_reanalysis,
    )
    monkeypatch.setattr(
        service,
        "process_article",
        unexpected_processing,
    )

    result = process_article_batch(
        [],
        limit=5,
        reanalyze=False,
    )

    assert captured["article_ids"] == []
    assert result == {
        "selection_mode": "unprocessed_only",
        "eligible_article_count": 0,
        "ineligible_or_missing_count": 0,
        "requested_article_count": 0,
        "available_unprocessed_count": 0,
        "selected_article_count": 0,
        "deferred_article_count": 0,
        "unavailable_or_processed_count": 0,
        "successful_count": 0,
        "unsuccessful_count": 0,
        "status_counts": {},
        "results": [],
    }


def test_process_article_batch_reanalysis_limit_and_progress(
    monkeypatch,
):
    articles = [
        SimpleNamespace(
            id=1,
            title="First",
        ),
        SimpleNamespace(
            id=2,
            title="Second",
        ),
        SimpleNamespace(
            id=3,
            title="Third",
        ),
    ]

    requested_ids = [
        1,
        2,
        2,
        3,
        4,
    ]

    repository_calls = []
    process_calls = []
    progress_events = []

    def fake_get_articles(article_ids):
        repository_calls.append(article_ids)
        return articles

    def unexpected_unprocessed(article_ids):
        raise AssertionError(
            "Unprocessed-only repository should "
            "not be called."
        )

    def fake_process(
        article,
        *,
        include_otx,
        include_cve,
    ):
        process_calls.append((
            article.id,
            include_otx,
            include_cve,
        ))

        return {
            "article_id": article.id,
            "status": (
                "processed"
                if article.id == 1
                else "processed_with_warnings"
            ),
            "marked_processed": True,
            "warnings": (
                []
                if article.id == 1
                else ["Optional enrichment failed."]
            ),
        }

    monkeypatch.setattr(
        service,
        "get_articles_by_ids",
        fake_get_articles,
    )
    monkeypatch.setattr(
        service,
        "get_unprocessed_articles_by_ids",
        unexpected_unprocessed,
    )
    monkeypatch.setattr(
        service,
        "process_article",
        fake_process,
    )

    result = process_article_batch(
        requested_ids,
        limit=2,
        include_otx=False,
        include_cve=False,
        reanalyze=True,
        progress_callback=progress_events.append,
    )

    assert repository_calls == [
        requested_ids,
    ]
    assert process_calls == [
        (
            1,
            False,
            False,
        ),
        (
            2,
            False,
            False,
        ),
    ]

    assert progress_events == [
        {
            "event": "started",
            "position": 1,
            "total": 2,
            "article_id": 1,
            "title": "First",
        },
        {
            "event": "finished",
            "position": 1,
            "total": 2,
            "article_id": 1,
            "title": "First",
            "status": "processed",
        },
        {
            "event": "started",
            "position": 2,
            "total": 2,
            "article_id": 2,
            "title": "Second",
        },
        {
            "event": "finished",
            "position": 2,
            "total": 2,
            "article_id": 2,
            "title": "Second",
            "status": (
                "processed_with_warnings"
            ),
        },
    ]

    assert result["selection_mode"] == (
        "explicit_reanalysis"
    )
    assert result["eligible_article_count"] == 3
    assert result["requested_article_count"] == 4
    assert result[
        "ineligible_or_missing_count"
    ] == 1
    assert result["selected_article_count"] == 2
    assert result["deferred_article_count"] == 1
    assert result["successful_count"] == 2
    assert result["unsuccessful_count"] == 0
    assert result["status_counts"] == {
        "processed": 1,
        "processed_with_warnings": 1,
    }


def test_process_article_batch_isolates_article_failure(
    monkeypatch,
):
    articles = [
        SimpleNamespace(
            id=10,
            title="Successful",
        ),
        SimpleNamespace(
            id=20,
            title="Failed",
        ),
        SimpleNamespace(
            id=30,
            title="Analysis failed",
        ),
    ]

    calls = []

    monkeypatch.setattr(
        service,
        "get_unprocessed_articles_by_ids",
        lambda article_ids: articles,
    )

    def fake_process(
        article,
        *,
        include_otx,
        include_cve,
    ):
        calls.append(article.id)

        if article.id == 20:
            raise RuntimeError(
                "Simulated processing failure"
            )

        if article.id == 30:
            return {
                "article_id": 30,
                "status": "analysis_failed",
                "marked_processed": False,
                "warnings": [
                    "No safe analysis.",
                ],
            }

        return {
            "article_id": 10,
            "status": "processed",
            "marked_processed": True,
            "warnings": [],
        }

    monkeypatch.setattr(
        service,
        "process_article",
        fake_process,
    )

    result = process_article_batch(
        [
            10,
            20,
            30,
        ],
        limit=3,
        include_otx=True,
        include_cve=True,
        reanalyze=False,
    )

    assert calls == [
        10,
        20,
        30,
    ]

    assert result["selection_mode"] == (
        "unprocessed_only"
    )
    assert result["successful_count"] == 1
    assert result["unsuccessful_count"] == 2
    assert result["status_counts"] == {
        "processed": 1,
        "failed": 1,
        "analysis_failed": 1,
    }

    assert result["results"][1] == {
        "article_id": 20,
        "status": "failed",
        "error": (
            "RuntimeError: "
            "Simulated processing failure"
        ),
        "marked_processed": False,
        "warnings": [
            "Mandatory article processing failed.",
        ],
    }
