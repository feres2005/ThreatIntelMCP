from datetime import datetime, timezone

import pytest

import pipeline.curated_report_service as service


pytestmark = pytest.mark.unit


def test_ingest_curated_report_uses_internal_services(
    monkeypatch,
):
    events = []

    report = {
        "article": {
            "title": (
                "Hunting MacSync Stealer infrastructure "
                "through behavioral pivots"
            ),
            "link": (
                "https://www.microsoft.com/en-us/security/"
                "blog/2026/08/18/hunting-macsync-stealer-"
                "infrastructure-through-behavioral-pivots/"
            ),
            "published": datetime(
                2026,
                8,
                18,
                tzinfo=timezone.utc,
            ),
            "summary": (
                "Microsoft linked rotating domains to "
                "MacSync Stealer infrastructure."
            ),
            "source": "microsoft_security_blog",
        },
        "analysis": {
            "summary": (
                "MacSync Stealer uses rotating domains "
                "for payload delivery and exfiltration."
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
        "iocs": [
            "aihealthring.com",
            "cabinrentalsnc.com",
        ],
    }

    normalized_iocs = [
        {
            "indicator": "aihealthring.com",
            "indicator_type": "domain",
        },
        {
            "indicator": "cabinrentalsnc.com",
            "indicator_type": "domain",
        },
    ]

    def fake_normalize_ioc_list(values):
        events.append(("normalize", values))
        return normalized_iocs

    def fake_insert_article(article):
        events.append(("insert", article))
        return {
            "article_id": 16001,
            "inserted": True,
        }

    def fake_save_article_analysis(analysis):
        events.append(("save_analysis", analysis))

    def fake_replace_article_iocs(article_id, iocs):
        events.append(
            ("replace_iocs", article_id, iocs)
        )
        return {
            "article_id": article_id,
            "deleted_count": 0,
            "inserted_count": 2,
        }

    def fake_mark_article_as_processed(article_id):
        events.append(("mark_processed", article_id))

    def fake_index_article(article_id):
        events.append(("index", article_id))
        return {
            "article_id": article_id,
            "status": "updated",
        }

    monkeypatch.setattr(
        service,
        "normalize_ioc_list",
        fake_normalize_ioc_list,
    )
    monkeypatch.setattr(
        service,
        "insert_article",
        fake_insert_article,
    )
    monkeypatch.setattr(
        service,
        "save_article_analysis",
        fake_save_article_analysis,
    )
    monkeypatch.setattr(
        service,
        "replace_article_iocs",
        fake_replace_article_iocs,
    )
    monkeypatch.setattr(
        service,
        "mark_article_as_processed",
        fake_mark_article_as_processed,
    )
    monkeypatch.setattr(
        service,
        "index_article",
        fake_index_article,
    )

    result = service.ingest_curated_report(report)

    assert result == {
        "status": "imported",
        "article_id": 16001,
        "inserted": True,
        "ioc_count": 2,
        "ioc_replacement": {
            "article_id": 16001,
            "deleted_count": 0,
            "inserted_count": 2,
        },
        "embedding_status": "updated",
    }

    saved_analysis = events[2][1]

    assert saved_analysis["article_id"] == 16001
    assert saved_analysis["iocs"] == [
        "aihealthring.com",
        "cabinrentalsnc.com",
    ]

    assert events == [
        ("normalize", report["iocs"]),
        ("insert", report["article"]),
        ("save_analysis", saved_analysis),
        (
            "replace_iocs",
            16001,
            normalized_iocs,
        ),
        ("mark_processed", 16001),
        ("index", 16001),
    ]
@pytest.mark.parametrize(
    "ioc_values",
    [
        [],
        ["not an IOC"],
        [
            "aihealthring.com",
            "not an IOC",
        ],
    ],
)
def test_ingest_curated_report_rejects_invalid_iocs_before_writes(
    monkeypatch,
    ioc_values,
):
    def fail_if_called(article):
        pytest.fail(
            "The database must not be modified."
        )

    monkeypatch.setattr(
        service,
        "insert_article",
        fail_if_called,
    )

    with pytest.raises(
        ValueError,
        match=(
            "Curated report IOCs must be a "
            "non-empty list of valid, unique "
            "indicators."
        ),
    ):
        service.ingest_curated_report({
            "iocs": ioc_values,
        })
        