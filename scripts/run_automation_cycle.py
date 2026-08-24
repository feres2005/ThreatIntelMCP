import argparse
import json
from pathlib import Path
import logging
from time import perf_counter

from observability.logging_config import (
    configure_logging,
)
from pipeline.automation_cycle_service import (
    run_automation_cycle,
)

logger = logging.getLogger(__name__)

def _build_argument_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Run one controlled ThreatIntelMCP "
            "automation cycle."
        )
    )

    parser.add_argument(
        "--processing-limit",
        type=int,
        default=5,
        help=(
            "Maximum number of pending articles "
            "to process. Default: 5."
        ),
    )
    parser.add_argument(
        "--embedding-limit",
        type=int,
        default=25,
        help=(
            "Maximum number of missing article "
            "embeddings to create. Default: 25."
        ),
    )
    parser.add_argument(
        "--include-otx",
        action="store_true",
        help=(
            "Enable OTX enrichment while "
            "processing articles."
        ),
    )
    parser.add_argument(
        "--include-cve",
        action="store_true",
        help=(
            "Enable CVE enrichment while "
            "processing articles."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help=(
            "Optional JSON output file. Parent "
            "directories are created automatically."
        ),
    )

    return parser


def _write_report(output_path, report_text):
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = output_path.with_suffix(
        output_path.suffix + ".tmp"
    )

    temporary_path.write_text(
        report_text,
        encoding="utf-8",
    )

    temporary_path.replace(output_path)


def main(arguments=None):
    configure_logging()
    parser = _build_argument_parser()
    options = parser.parse_args(arguments)

    started_at = perf_counter()

    logger.info(
        (
            "Automation cycle started: "
            "processing_limit=%s, "
            "embedding_limit=%s, "
            "include_otx=%s, include_cve=%s"
        ),
        options.processing_limit,
        options.embedding_limit,
        options.include_otx,
        options.include_cve,
    )

    try:
        result = run_automation_cycle(
            processing_limit=(
                options.processing_limit
            ),
            embedding_limit=(
                options.embedding_limit
            ),
            include_otx=options.include_otx,
            include_cve=options.include_cve,
        )
    except Exception:
        logger.exception(
            (
                "Automation cycle failed before "
                "producing a structured result."
            )
        )
        raise

    duration_seconds = (
        perf_counter() - started_at
    )

    logger.info(
        (
            "Automation cycle finished with "
            "status %s in %.3f seconds"
        ),
        result["status"],
        duration_seconds,
    )

    report_text = json.dumps(
        result,
        indent=2,
        ensure_ascii=False,
        default=str,
    )

    print(report_text)

    if options.output is not None:
        _write_report(
            options.output,
            report_text,
        )

    if result["status"] == "completed":
        return 0

    if (
        result["status"]
        == "completed_with_warnings"
    ):
        return 2

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
