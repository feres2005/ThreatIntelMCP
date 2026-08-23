import pytest

from enrichment.ioc_normalizer import (
    normalize_ioc_list,
)
from scripts.import_macsync_report import (
    MACSYNC_REPORT,
)


pytestmark = pytest.mark.unit


def test_macsync_report_contains_verified_domains():
    iocs = MACSYNC_REPORT["iocs"]
    normalized_iocs = normalize_ioc_list(iocs)

    assert len(iocs) == 31
    assert len(set(iocs)) == 31
    assert len(normalized_iocs) == 31

    assert {
        ioc["indicator_type"]
        for ioc in normalized_iocs
    } == {"domain"}

    assert {
        "aihealthring.com",
        "cabinrentalsnc.com",
        "chatbasedos.com",
        "wvaeagent.com",
    }.issubset(iocs)

    assert MACSYNC_REPORT["article"]["source"] == (
        "microsoft_security_blog"
    )
    assert MACSYNC_REPORT["analysis"]["malware"] == [
        "MacSync Stealer"
    ]