import argparse
import json
from datetime import datetime, timezone

from enrichment.ioc_normalizer import (
    normalize_ioc_list,
)
from pipeline.curated_report_service import (
    ingest_curated_report,
)


MACSYNC_REPORT_URL = (
    "https://www.microsoft.com/en-us/security/blog/"
    "2026/08/18/hunting-macsync-stealer-"
    "infrastructure-through-behavioral-pivots/"
)

MACSYNC_DOMAINS = [
    "aihealthring.com",
    "cabinrentalsnc.com",
    "chatbasedos.com",
    "commercialroofingsd.com",
    "dogtrainersgeorgia.com",
    "fintelliganceai.com",
    "homeinspectionsdelaware.com",
    "intopython.com",
    "lalandscapelighting.com",
    "lumenagnet.com",
    "marbellaresales.com",
    "miamipcsupport.com",
    "moldinspectiondayton.com",
    "nailscanai.com",
    "newjerseypetsitter.com",
    "numericagent.com",
    "oaklandwaterdamage.com",
    "oklahomawarehousing.com",
    "olympiapetemergency.com",
    "peaecagent.com",
    "plasmaticsystems.com",
    "plethorawallet.com",
    "premierrentalpurchase.com",
    "ricewaterbeauty.com",
    "rvieragent.com",
    "sandiegotkd.com",
    "secueragent.com",
    "shiledagent.com",
    "syracusefertilitycenter.com",
    "vastbets.com",
    "wvaeagent.com",
]

MACSYNC_REPORT = {
    "article": {
        "title": (
            "Hunting MacSync Stealer infrastructure "
            "through behavioral pivots"
        ),
        "link": MACSYNC_REPORT_URL,
        "published": datetime(
            2026,
            8,
            18,
            tzinfo=timezone.utc,
        ),
        "summary": (
            "Microsoft correlated recurring endpoint "
            "and network behavior with rotating "
            "MacSync Stealer infrastructure."
        ),
        "source": "microsoft_security_blog",
    },
    "analysis": {
        "summary": (
            "MacSync Stealer uses rotating domains for "
            "payload retrieval, command-and-control, "
            "data staging, and exfiltration on macOS."
        ),
        "classification": [
            "malware",
            "information-stealer",
        ],
        "severity": "High",
        "confidence_score": 0.95,
        "cves": [],
        "malware": ["MacSync Stealer"],
        "mitre_techniques": [
            "T1059.004",
            "T1041",
        ],
        "apt_groups": [],
        "targeted_sectors": [],
        "affected_technologies": ["macOS"],
    },
    "iocs": MACSYNC_DOMAINS,
}


def validate_macsync_report():
    normalized_iocs = normalize_ioc_list(
        MACSYNC_REPORT["iocs"]
    )

    return {
        "mode": "validation_only",
        "source": (
            MACSYNC_REPORT["article"]["source"]
        ),
        "report_url": MACSYNC_REPORT_URL,
        "declared_ioc_count": len(
            MACSYNC_REPORT["iocs"]
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
            == len(MACSYNC_REPORT["iocs"])
        ),
    }


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Validate or import the curated Microsoft "
            "MacSync Stealer report."
        ),
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help=(
            "Persist the curated report and its IOCs. "
            "Without this flag, validation is read-only."
        ),
    )
    arguments = parser.parse_args()

    if arguments.apply:
        result = ingest_curated_report(
            MACSYNC_REPORT
        )
    else:
        result = validate_macsync_report()

    print(json.dumps(
        result,
        indent=2,
        default=str,
    ))


if __name__ == "__main__":
    main()