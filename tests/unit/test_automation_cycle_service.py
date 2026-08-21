import pytest

import pipeline.automation_cycle_service as service
from pipeline.automation_cycle_service import (
    _run_cycle_step,
    _step_has_problem,
    _validate_limit,
    run_automation_cycle,
)


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "value",
    [
        1,
        20,
    ],
)
def test_validate_limit_accepts_valid_boundaries(
    value,
):
    assert _validate_limit(
        value,
        20,
        "Test limit",
    ) is None


@pytest.mark.parametrize(
    "value",
    [
        None,
        0,
        -1,
        True,
        "5",
        5.0,
        [],
    ],
)
def test_validate_limit_rejects_invalid_values(
    value,
):
    with pytest.raises(ValueError) as error_info:
        _validate_limit(
            value,
            20,
            "Test limit",
        )

    assert str(error_info.value) == (
        "Test limit must be a positive integer."
    )


def test_validate_limit_rejects_value_above_maximum():
    with pytest.raises(ValueError) as error_info:
        _validate_limit(
            21,
            20,
            "Test limit",
        )

    assert str(error_info.value) == (
        "Test limit cannot exceed 20."
    )


def test_run_cycle_step_returns_success_result():
    expected = {
        "operation": "test",
        "status": "completed",
    }

    assert _run_cycle_step(
        "test",
        lambda: expected,
    ) is expected


@pytest.mark.parametrize(
    ("exception", "expected_error"),
    [
        (
            RuntimeError("simulated failure"),
            (
                "RuntimeError: simulated failure"
            ),
        ),
        (
            ValueError("invalid value"),
            "ValueError: invalid value",
        ),
    ],
)
def test_run_cycle_step_isolates_exceptions(
    exception,
    expected_error,
):
    def failing_operation():
        raise exception

    assert _run_cycle_step(
        "test_operation",
        failing_operation,
    ) == {
        "operation": "test_operation",
        "status": "failed",
        "error": expected_error,
    }


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (
            {
                "status": "failed",
            },
            True,
        ),
        (
            {
                "status": (
                    "completed_with_warnings"
                ),
            },
            True,
        ),
        (
            {
                "status": "completed",
                "failed_count": 1,
            },
            True,
        ),
        (
            {
                "status": "completed",
                "unsuccessful_count": 1,
            },
            True,
        ),
        (
            {
                "status": "completed",
                "failed_count": 0,
                "unsuccessful_count": 0,
            },
            False,
        ),
        (
            {
                "health_status": "healthy",
            },
            False,
        ),
    ],
)
def test_step_has_problem(
    result,
    expected,
):
    assert _step_has_problem(result) is expected


@pytest.mark.parametrize(
    "arguments",
    [
        {
            "processing_limit": 0,
        },
        {
            "embedding_limit": 0,
        },
        {
            "include_otx": 1,
        },
        {
            "include_cve": "false",
        },
    ],
)
def test_run_automation_cycle_rejects_invalid_arguments(
    arguments,
):
    with pytest.raises(ValueError):
        run_automation_cycle(
            **arguments
        )


def test_run_automation_cycle_completes_successfully(
    monkeypatch,
):
    events = []

    status_before = {
        "operation": "get_pipeline_status",
        "health_status": "healthy",
    }
    status_after = {
        "operation": "get_pipeline_status",
        "health_status": "healthy",
    }
    statuses = iter([
        status_before,
        status_after,
    ])

    ingestion_result = {
        "operation": "rss_ingestion",
        "status": "completed",
        "failed_count": 0,
    }
    processing_result = {
        "operation": "process_pending_articles",
        "status": "completed",
        "unsuccessful_count": 0,
    }
    embedding_result = {
        "operation": "index_pending_embeddings",
        "status": "completed",
        "unsuccessful_count": 0,
    }

    def fake_status():
        events.append("status")
        return next(statuses)

    def fake_ingestion():
        events.append("ingestion")
        return ingestion_result

    def fake_processing(
        limit,
        *,
        include_otx,
        include_cve,
    ):
        events.append((
            "processing",
            limit,
            include_otx,
            include_cve,
        ))
        return processing_result

    def fake_embedding(limit):
        events.append((
            "embedding",
            limit,
        ))
        return embedding_result

    monkeypatch.setattr(
        service,
        "get_pipeline_status",
        fake_status,
    )
    monkeypatch.setattr(
        service,
        "ingest_rss_articles",
        fake_ingestion,
    )
    monkeypatch.setattr(
        service,
        "process_pending_articles",
        fake_processing,
    )
    monkeypatch.setattr(
        service,
        "index_pending_embeddings",
        fake_embedding,
    )

    result = run_automation_cycle(
        processing_limit=3,
        embedding_limit=10,
        include_otx=True,
        include_cve=True,
    )

    assert events == [
        "status",
        "ingestion",
        (
            "processing",
            3,
            True,
            True,
        ),
        (
            "embedding",
            10,
        ),
        "status",
    ]

    assert result["status"] == "completed"
    assert result["problematic_steps"] == []
    assert result["status_before"] is (
        status_before
    )
    assert result["status_after"] is status_after
    assert result["steps"] == {
        "rss_ingestion": ingestion_result,
        "article_processing": processing_result,
        "embedding_indexing": embedding_result,
    }


def test_run_automation_cycle_reports_warning_steps(
    monkeypatch,
):
    statuses = iter([
        {
            "health_status": "healthy",
        },
        {
            "health_status": "healthy",
        },
    ])

    monkeypatch.setattr(
        service,
        "get_pipeline_status",
        lambda: next(statuses),
    )
    monkeypatch.setattr(
        service,
        "ingest_rss_articles",
        lambda: {
            "status": (
                "completed_with_warnings"
            ),
        },
    )
    monkeypatch.setattr(
        service,
        "process_pending_articles",
        lambda *args, **kwargs: {
            "status": "completed",
            "unsuccessful_count": 1,
        },
    )
    monkeypatch.setattr(
        service,
        "index_pending_embeddings",
        lambda limit: {
            "status": "completed",
            "failed_count": 1,
        },
    )

    result = run_automation_cycle()

    assert result["status"] == (
        "completed_with_warnings"
    )
    assert result["problematic_steps"] == [
        "rss_ingestion",
        "article_processing",
        "embedding_indexing",
    ]


def test_run_automation_cycle_reports_status_problems(
    monkeypatch,
):
    statuses = iter([
        {
            "status": "failed",
        },
        RuntimeError(
            "final status unavailable"
        ),
    ])

    def fake_status():
        result = next(statuses)

        if isinstance(result, Exception):
            raise result

        return result

    monkeypatch.setattr(
        service,
        "get_pipeline_status",
        fake_status,
    )
    monkeypatch.setattr(
        service,
        "ingest_rss_articles",
        lambda: {
            "status": "completed",
        },
    )
    monkeypatch.setattr(
        service,
        "process_pending_articles",
        lambda *args, **kwargs: {
            "status": "completed",
        },
    )
    monkeypatch.setattr(
        service,
        "index_pending_embeddings",
        lambda limit: {
            "status": "completed",
        },
    )

    result = run_automation_cycle()

    assert result["status"] == (
        "completed_with_warnings"
    )
    assert result["problematic_steps"] == [
        "status_before",
        "status_after",
    ]
    assert result["status_after"] == {
        "operation": "get_pipeline_status_after",
        "status": "failed",
        "error": (
            "RuntimeError: "
            "final status unavailable"
        ),
    }


def test_run_automation_cycle_fails_when_all_steps_fail(
    monkeypatch,
):
    events = []

    def failing_ingestion():
        events.append("ingestion")
        raise RuntimeError("RSS failure")

    def failing_processing(*args, **kwargs):
        events.append("processing")
        raise RuntimeError("processing failure")

    def failing_embedding(limit):
        events.append("embedding")
        raise RuntimeError("embedding failure")

    monkeypatch.setattr(
        service,
        "get_pipeline_status",
        lambda: {
            "health_status": "healthy",
        },
    )
    monkeypatch.setattr(
        service,
        "ingest_rss_articles",
        failing_ingestion,
    )
    monkeypatch.setattr(
        service,
        "process_pending_articles",
        failing_processing,
    )
    monkeypatch.setattr(
        service,
        "index_pending_embeddings",
        failing_embedding,
    )

    result = run_automation_cycle()

    assert events == [
        "ingestion",
        "processing",
        "embedding",
    ]
    assert result["status"] == "failed"
    assert result["problematic_steps"] == [
        "rss_ingestion",
        "article_processing",
        "embedding_indexing",
    ]
