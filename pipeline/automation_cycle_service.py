import logging
from time import perf_counter
from pipeline.ingestion_service import (
    ingest_rss_articles,
)
from pipeline.automation_service import (
    MAX_EMBEDDING_BATCH_SIZE,
    MAX_PROCESSING_BATCH_SIZE,
    get_pipeline_status,
    index_pending_embeddings,
    process_pending_articles,
)


logger = logging.getLogger(__name__)


def _validate_limit(value, maximum, label):
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value <= 0
    ):
        raise ValueError(
            f"{label} must be a positive integer."
        )

    if value > maximum:
        raise ValueError(
            f"{label} cannot exceed {maximum}."
        )


def _run_cycle_step(operation, function):
    started_at = perf_counter()

    logger.info(
        "Automation step started: %s",
        operation,
    )

    try:
        result = function()
    except Exception as error:
        duration_seconds = (
            perf_counter() - started_at
        )

        logger.exception(
            (
                "Automation step failed: %s "
                "after %.3f seconds"
            ),
            operation,
            duration_seconds,
        )

        return {
            "operation": operation,
            "status": "failed",
            "error": (
                f"{type(error).__name__}: "
                f"{error}"
            ),
        }

    duration_seconds = (
        perf_counter() - started_at
    )

    if isinstance(result, dict):
        result_status = result.get(
            "status",
            "not_reported",
        )
    else:
        result_status = "not_reported"

    logger.info(
        (
            "Automation step finished: %s "
            "with status %s in %.3f seconds"
        ),
        operation,
        result_status,
        duration_seconds,
    )

    return result

def _step_has_problem(result):
    if result.get("status") in {
        "failed",
        "completed_with_warnings",
    }:
        return True

    if result.get("failed_count", 0) > 0:
        return True

    if result.get("unsuccessful_count", 0) > 0:
        return True

    return False


def run_automation_cycle(
    processing_limit=5,
    embedding_limit=25,
    *,
    include_otx=False,
    include_cve=False,
):
    _validate_limit(
        processing_limit,
        MAX_PROCESSING_BATCH_SIZE,
        "Processing limit",
    )
    _validate_limit(
        embedding_limit,
        MAX_EMBEDDING_BATCH_SIZE,
        "Embedding limit",
    )

    if not isinstance(include_otx, bool):
        raise ValueError(
            "include_otx must be a boolean."
        )

    if not isinstance(include_cve, bool):
        raise ValueError(
            "include_cve must be a boolean."
        )

    status_before = _run_cycle_step(
        "get_pipeline_status_before",
        get_pipeline_status,
    )

    ingestion_result = _run_cycle_step(
        "rss_ingestion",
        ingest_rss_articles,
    )

    processing_result = _run_cycle_step(
        "process_pending_articles",
        lambda: process_pending_articles(
            processing_limit,
            include_otx=include_otx,
            include_cve=include_cve,
        ),
    )

    embedding_result = _run_cycle_step(
        "index_pending_embeddings",
        lambda: index_pending_embeddings(
            embedding_limit
        ),
    )

    steps = {
        "rss_ingestion": ingestion_result,
        "article_processing": processing_result,
        "embedding_indexing": embedding_result,
    }

    status_after = _run_cycle_step(
        "get_pipeline_status_after",
        get_pipeline_status,
    )

    problematic_steps = [
        step_name
        for step_name, result in steps.items()
        if _step_has_problem(result)
    ]
    if _step_has_problem(status_before):
        problematic_steps.insert(
            0,
            "status_before",
        )

    if _step_has_problem(status_after):
        problematic_steps.append(
            "status_after"
        )

    failed_step_count = sum(
        result.get("status") == "failed"
        for result in steps.values()
    )

    if failed_step_count == len(steps):
        cycle_status = "failed"
    elif problematic_steps:
        cycle_status = "completed_with_warnings"
    else:
        cycle_status = "completed"


    return {
        "operation": "run_automation_cycle",
        "status": cycle_status,
        "processing_limit": processing_limit,
        "embedding_limit": embedding_limit,
        "include_otx": include_otx,
        "include_cve": include_cve,
        "problematic_steps": problematic_steps,
        "status_before": status_before,
        "steps": steps,
        "status_after": status_after,
    }
