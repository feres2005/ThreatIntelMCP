import argparse

from database.article_repository import (
    get_unprocessed_articles_by_ids,
    get_articles_by_ids,
)
from pipeline.article_batch_service import (
    process_article_batch,
)


THREAT_ARTICLE_IDS = [
    11977,
    13228,
    12672,
    11954,
    13210,
    12641,
    11046,
    12751,
    13263,
    13209,
    13088,
    13251,
]

CONTROL_ARTICLE_IDS = [
    13265,
    13261,
]

BOUNDARY_ARTICLE_IDS = [
    13258,
]


PILOT_ARTICLE_IDS = [
    11977,
    13265,
    13228,
    12672,
    11954,
    13210,
    13261,
    12641,
    11046,
    12751,
    13263,
    13258,
    13209,
    13088,
    13251,
]


def positive_integer(value):
    try:
        parsed_value = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "The value must be an integer."
        ) from error

    if parsed_value <= 0:
        raise argparse.ArgumentTypeError(
            "The value must be greater than zero."
        )

    return parsed_value


def get_article_category(article_id):
    if article_id in THREAT_ARTICLE_IDS:
        return "THREAT"

    if article_id in CONTROL_ARTICLE_IDS:
        return "CONTROL"

    if article_id in BOUNDARY_ARTICLE_IDS:
        return "BOUNDARY"

    return "UNKNOWN"

def print_progress(event):
    article_id = event["article_id"]
    category = get_article_category(
        article_id
    )

    if event["event"] == "started":
        print()
        print(
            f"[{event['position']}/"
            f"{event['total']}] "
            f"{category} article "
            f"{article_id}"
        )
        print("Title:", event["title"])
        print(
            "Article processing started.",
            flush=True,
        )
        return

    print(
        "Processing status:",
        event["status"],
        flush=True,
    )


def print_result_summary(result):
    print()
    print(
        "Article result:",
        result["article_id"],
    )
    print("Status:", result["status"])

    analysis = result.get("analysis")

    if not isinstance(analysis, dict):
        print("No stored AI analysis.")
    else:
        print(
            "Severity:",
            analysis.get("severity"),
        )
        print(
            "AI confidence:",
            analysis.get(
                "confidence_score"
            ),
        )
        print(
            "Classification:",
            analysis.get(
                "classification",
                [],
            ),
        )
        print(
            "Raw AI IOCs:",
            analysis.get("iocs", []),
        )
        print(
            "CVEs:",
            analysis.get("cves", []),
        )
        print(
            "Malware:",
            analysis.get(
                "malware",
                [],
            ),
        )
        print(
            "MITRE techniques:",
            analysis.get(
                "mitre_techniques",
                [],
            ),
        )
        print(
            "APT groups:",
            analysis.get(
                "apt_groups",
                [],
            ),
        )

    ioc_processing = result.get(
        "ioc_processing"
    )

    if isinstance(ioc_processing, dict):
        print(
            "Typed IOCs:",
            ioc_processing.get(
                "normalized_iocs",
                [],
            ),
        )

    otx_enrichment = result.get(
        "otx_enrichment"
    )

    if isinstance(otx_enrichment, dict):
        print(
            "Successful OTX lookups:",
            otx_enrichment.get(
                "successful_lookup_count",
                0,
            ),
            "/",
            otx_enrichment.get(
                "lookup_count",
                0,
            ),
        )

    cve_enrichment = result.get(
        "cve_enrichment"
    )

    if isinstance(cve_enrichment, dict):
        print(
            "Available CVE enrichments:",
            cve_enrichment.get(
                "available_count",
                0,
            ),
            "/",
            cve_enrichment.get(
                "lookup_count",
                0,
            ),
        )

    warnings = result.get(
        "warnings",
        [],
    )

    if warnings:
        print("Warnings:")

        for warning in warnings:
            print("-", warning)


def print_batch_summary(batch_result):
    print()
    print("=" * 70)
    print("PILOT BATCH SUMMARY")
    print("=" * 70)

    print(
        "Pilot articles requested:",
        batch_result[
            "requested_article_count"
        ],
    )
    print(
        "Selection mode:",
        batch_result["selection_mode"],
    )
    print(
        "Eligible before this run:",
        batch_result[
            "eligible_article_count"
        ],
    )
    print(
        "Selected in this run:",
        batch_result[
            "selected_article_count"
        ],
    )
    print(
        "Deferred to later runs:",
        batch_result[
            "deferred_article_count"
        ],
    )
    print(
        "Ineligible or missing:",
        batch_result[
            "ineligible_or_missing_count"
        ],
    )
    print(
        "Successful in this run:",
        batch_result[
            "successful_count"
        ],
    )
    print(
        "Unsuccessful in this run:",
        batch_result[
            "unsuccessful_count"
        ],
    )
    print(
        "Status distribution:",
        batch_result["status_counts"],
    )

    successful_results = [
        result
        for result in batch_result["results"]
        if result.get("analysis")
        is not None
    ]

    articles_with_raw_iocs = sum(
        bool(
            result["analysis"].get(
                "iocs",
                [],
            )
        )
        for result in successful_results
    )

    articles_with_typed_iocs = sum(
        bool(
            result.get(
                "ioc_processing",
                {},
            ).get(
                "normalized_iocs",
                [],
            )
        )
        for result in successful_results
    )

    total_raw_iocs = sum(
        len(
            result["analysis"].get(
                "iocs",
                [],
            )
        )
        for result in successful_results
    )

    total_typed_iocs = sum(
        len(
            result.get(
                "ioc_processing",
                {},
            ).get(
                "normalized_iocs",
                [],
            )
        )
        for result in successful_results
    )

    total_cves = sum(
        len(
            result["analysis"].get(
                "cves",
                [],
            )
        )
        for result in successful_results
    )

    print()
    print("Extraction statistics:")
    print(
        "Articles with raw AI IOCs:",
        articles_with_raw_iocs,
    )
    print(
        "Articles with typed IOCs:",
        articles_with_typed_iocs,
    )
    print(
        "Total raw AI IOCs:",
        total_raw_iocs,
    )
    print(
        "Total valid typed IOCs:",
        total_typed_iocs,
    )
    print(
        "Total extracted CVEs:",
        total_cves,
    )


def run_dry_run(limit, reanalyze=False):
    if reanalyze:
        articles = get_articles_by_ids(
            PILOT_ARTICLE_IDS
        )
        selection_mode = (
            "explicit reanalysis"
        )
    else:
        articles = (
            get_unprocessed_articles_by_ids(
                PILOT_ARTICLE_IDS
            )
        )
        selection_mode = (
            "unprocessed articles only"
        )

    selected_articles = articles[:limit]

    print("Pilot dry run")
    print("Selection mode:", selection_mode)
    print(
    "Total pilot size:",
    len(PILOT_ARTICLE_IDS),
    ) 
    print(
        "Eligible in selected mode:",
        len(articles),
    )
    print(
        "Selected by this run:",
        len(selected_articles),
    )

    for position, article in enumerate(
        selected_articles,
        start=1,
    ):
        print()
        print(
            f"{position}. "
            f"[{get_article_category(article.id)}] "
            f"ID {article.id}"
        )
        print("Title:", article.title)

    print()
    print(
        "Dry run completed. "
        "No article was analyzed or modified."
    )


def build_argument_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Analyze the fixed Day 4.5 "
            "article pilot in small batches."
        )
    )

    parser.add_argument(
        "--limit",
        type=positive_integer,
        default=5,
        help=(
            "Maximum number of remaining "
            "pilot articles to process."
        ),
    )

    parser.add_argument(
      "--with-otx",
      action="store_true",
      help=(
        "Enable OTX enrichment. "
        "Disabled by default for the pilot."
      ),
    )

    parser.add_argument(
      "--with-cve",
      action="store_true",
      help=(
        "Enable CVE enrichment. "
        "Disabled by default for the pilot."
      ),
    )
    parser.add_argument(
        "--reanalyze",
        action="store_true",
        help=(
            "Explicitly allow the fixed pilot "
            "articles to be analyzed again. "
            "Existing analyses will be updated."
        ),
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Display the selected articles "
            "without processing them."
        ),
    )

    return parser


def main():
    parser = build_argument_parser()
    arguments = parser.parse_args()

    if arguments.dry_run:
        run_dry_run(
            arguments.limit,
            reanalyze=arguments.reanalyze,
        )
        return 0

    batch_result = process_article_batch(
        PILOT_ARTICLE_IDS,
        limit=arguments.limit,
        include_otx=arguments.with_otx,
        include_cve=arguments.with_cve,
        reanalyze=arguments.reanalyze,
        progress_callback=print_progress,
    )

    for result in batch_result["results"]:
        print_result_summary(result)

    print_batch_summary(batch_result)

    if batch_result["unsuccessful_count"] > 0:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())