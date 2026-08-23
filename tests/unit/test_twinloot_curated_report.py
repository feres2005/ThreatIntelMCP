from collections import Counter

import pytest

from enrichment.ioc_normalizer import normalize_ioc_list
from scripts.import_twinloot_report import (
    TWINLOOT_REPORT,
)


pytestmark = pytest.mark.unit


def test_twinloot_report_contains_declared_iocs():
    declared_iocs = TWINLOOT_REPORT["iocs"]
    normalized_iocs = normalize_ioc_list(
        declared_iocs
    )

    assert len(declared_iocs) == 9
    assert len(normalized_iocs) == 9

    normalized_keys = {
        (
            ioc["indicator"],
            ioc["indicator_type"],
        )
        for ioc in normalized_iocs
    }

    assert len(normalized_keys) == 9

    type_counts = Counter(
        ioc["indicator_type"]
        for ioc in normalized_iocs
    )

    assert type_counts == {
        "FileHash-SHA256": 4,
        "domain": 4,
        "IPv4": 1,
    }

    indicators = {
        ioc["indicator"]
        for ioc in normalized_iocs
    }

    assert "193.24.211.221" in indicators
    assert "sharepointx.th2ch.com" in indicators
    assert (
        "2f1aa13fbdd8f5cdfe0838ecd4801a58"
        "81239ea096dd80f0af6ad1990c11418e"
        in indicators
    )

    assert (
        TWINLOOT_REPORT["article"]["source"]
        == "ontinue_research"
    )
    assert (
        TWINLOOT_REPORT["analysis"]["malware"]
        == ["TWINLOOT"]
    )