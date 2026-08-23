import argparse
import json
from datetime import datetime, timezone

from enrichment.ioc_normalizer import (
    normalize_ioc_list,
)
from pipeline.curated_report_service import (
    ingest_curated_report,
)


TWINLOOT_REPORT = {
    "article": {
        "title": (
            "Python implant hiding its entire C2 "
            "inside Microsoft 365 and Azure"
        ),
        "link": (
            "https://www.ontinue.com/resource/"
            "python-implant-hiding-its-entire-c2-"
            "inside-microsoft-365-azure/"
        ),
        "published": datetime(
            2026,
            7,
            27,
            tzinfo=timezone.utc,
        ),
        "summary": (
            "Ontinue researchers documented TWINLOOT, "
            "a modular Python implant using Microsoft "
            "SharePoint, Teams and Azure services for "
            "command-and-control, credential theft and "
            "payload delivery."
        ),
        "source": "ontinue_research",
    },
    "analysis": {
        "summary": (
            "TWINLOOT is a modular Python implant that "
            "uses trusted Microsoft 365 and Azure "
            "services for command-and-control. The "
            "campaign uses phishing, credential theft, "
            "proxying, persistence and encrypted payload "
            "delivery."
        ),
        "classification": [
            "malware",
            "credential-theft",
        ],
        "severity": "High",
        "confidence_score": 0.95,
        "iocs": [],
        "cves": [],
        "malware": [
            "TWINLOOT",
        ],
        "mitre_techniques": [
            "T1566.004",
            "T1056.002",
            "T1090",
            "T1102.001",
            "T1547.001",
        ],
        "apt_groups": [],
        "targeted_sectors": [],
        "affected_technologies": [
            "Windows",
            "Microsoft SharePoint",
            "Microsoft Teams",
            "Microsoft Edge",
            "Azure Blob Storage",
        ],
    },
    "iocs": [
        (
            "2f1aa13fbdd8f5cdfe0838ecd4801a58"
            "81239ea096dd80f0af6ad1990c11418e"
        ),
        (
            "dc12b303b6374e0e1e1b2583d5e60e7"
            "d1e6e5207e6254627c7069b3049198f82"
        ),
        (
            "0ca8367e52c0c64bd75b994a4dfe4b29"
            "a1d2eb1307932c91b50576b1e19d6fd9"
        ),
        (
            "16189a81eb537350cb5a3fff6cfa0b184"
            "44dbba6cdbe19e555c523b3a9fba191"
        ),
        "sharepointx.th2ch.com",
        "lpi-web.com",
        "193.24.211.221",
        "kerteransens.sharepoint.com",
        "034e10fbc291f2ce.blob.core.windows.net",
    ],
}


def build_validation_result():
    normalized_iocs = normalize_ioc_list(
        TWINLOOT_REPORT["iocs"]
    )

    return {
        "mode": "validation_only",
        "source": (
            TWINLOOT_REPORT["article"]["source"]
        ),
        "report_url": (
            TWINLOOT_REPORT["article"]["link"]
        ),
        "declared_ioc_count": len(
            TWINLOOT_REPORT["iocs"]
        ),
        "normalized_ioc_count": len(
            normalized_iocs
        ),
        "indicator_types": sorted({
            ioc["indicator_type"]
            for ioc in normalized_iocs
        }),
        "all_iocs_valid": (
            len(normalized_iocs)
            == len(TWINLOOT_REPORT["iocs"])
        ),
    }


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Validate or import the curated "
            "TWINLOOT threat report."
        )
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help=(
            "Persist the report to the configured "
            "PostgreSQL database."
        ),
    )
    arguments = parser.parse_args()

    if arguments.apply:
        result = ingest_curated_report(
            TWINLOOT_REPORT
        )
    else:
        result = build_validation_result()

    print(
        json.dumps(
            result,
            indent=2,
            default=str,
        )
    )


if __name__ == "__main__":
    main()