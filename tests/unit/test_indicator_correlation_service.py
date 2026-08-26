import pytest

import correlation.indicator_correlation_service as service
from correlation.indicator_correlation_service import (
    _collect_entity_evidence,
    correlate_indicator,
)


pytestmark = pytest.mark.unit


def test_collect_entity_evidence_handles_empty_correlations():
    assert _collect_entity_evidence(
        [],
        "malware",
    ) == []


def test_collect_entity_evidence_ignores_non_list_fields():
    correlations = [
        {
            "article": {
                "article_id": 1,
                "malware": None,
            },
        },
        {
            "article": {
                "article_id": 2,
                "malware": "Emotet",
            },
        },
    ]

    assert _collect_entity_evidence(
        correlations,
        "malware",
    ) == []


def test_collect_entity_evidence_normalizes_and_aggregates():
    correlations = [
        {
            "article": {
                "article_id": 2,
                "malware": [
                    "Zeus",
                    "Emotet",
                    None,
                    " ",
                ],
            },
        },
        {
            "article": {
                "article_id": 1,
                "malware": [
                    "emotet",
                    "TrickBot",
                ],
            },
        },
        {
            "article": {
                "article_id": 1,
                "malware": [
                    "EMOTET",
                ],
            },
        },
    ]

    assert _collect_entity_evidence(
        correlations,
        "malware",
    ) == [
        {
            "value": "Emotet",
            "supporting_article_count": 2,
            "supporting_article_ids": [
                2,
                1,
            ],
        },
        {
            "value": "TrickBot",
            "supporting_article_count": 1,
            "supporting_article_ids": [
                1,
            ],
        },
        {
            "value": "Zeus",
            "supporting_article_count": 1,
            "supporting_article_ids": [
                2,
            ],
        },
    ]


@pytest.mark.parametrize(
    "indicator",
    [
        None,
        "",
        "not-an-ioc",
        123,
        "localhost",
    ],
)
def test_correlate_indicator_rejects_invalid_iocs(
    indicator,
):
    with pytest.raises(ValueError) as error_info:
        correlate_indicator(
            indicator,
            include_otx=False,
        )

    assert str(error_info.value) == (
        "A valid supported IOC is required."
    )


def test_correlate_indicator_skips_external_lookups_when_disabled(
    monkeypatch,
):
    captured = {}

    def unexpected_otx_lookup(
        indicator,
        indicator_type,
    ):
        raise AssertionError(
            "OTX lookup should be disabled."
        )

    def unexpected_virustotal_lookup(
        indicator,
        indicator_type,
    ):
        raise AssertionError(
            "VirusTotal lookup should be disabled."
        )

    def fake_get_article_ids(
        indicator,
        indicator_type,
    ):
        captured["repository_arguments"] = (
            indicator,
            indicator_type,
        )
        return []

    def unexpected_article_lookup(article_id):
        raise AssertionError(
            "No article lookup was expected."
        )

    monkeypatch.setattr(
        service,
        "lookup_otx_indicator",
        unexpected_otx_lookup,
    )
    monkeypatch.setattr(
        service,
        "lookup_virustotal_indicator",
        unexpected_virustotal_lookup,
    )
    monkeypatch.setattr(
        service,
        "get_article_ids_by_indicator",
        fake_get_article_ids,
    )
    monkeypatch.setattr(
        service,
        "get_article_correlation_data",
        unexpected_article_lookup,
    )

    result = correlate_indicator(
        "Example[.]COM.",
        include_otx=False,
        include_virustotal=False,
    )

    assert captured["repository_arguments"] == (
        "example.com",
        "domain",
    )

    assert result == {
        "indicator": "example.com",
        "indicator_type": "domain",
        "supporting_article_count": 0,
        "supporting_article_ids": [],
        "supporting_articles": [],
        "related_entities": {
            "cves": [],
            "malware": [],
            "mitre_techniques": [],
            "apt_groups": [],
            "targeted_sectors": [],
            "affected_technologies": [],
        },
        "otx_enrichment": None,
        "virustotal_enrichment": None,
    }


def test_correlate_indicator_combines_articles_and_external_intelligence(
    monkeypatch,
):
    captured = {
        "article_lookups": [],
    }

    otx_result = {
        "indicator": "example.com",
        "pulse_count": 4,
    }
    virustotal_result = {
        "indicator": "example.com",
        "report_available": True,
        "malicious_count": 7,
        "total_engine_count": 60,
    }

    correlations = {
        2: {
            "article": {
                "article_id": 2,
                "title": "First article",
                "link": "https://example.test/2",
                "published": "2026-08-01",
                "severity": "High",
                "confidence_score": 0.9,
                "cves": [
                    "cve-2026-1234",
                ],
                "malware": [
                    "Emotet",
                ],
                "mitre_techniques": [
                    "t1566",
                ],
                "apt_groups": [],
                "targeted_sectors": [
                    "Finance",
                ],
                "affected_technologies": [
                    "Windows",
                ],
            },
        },
        1: None,
        3: {
            "article": {
                "article_id": 3,
                "title": "Second article",
                "link": "https://example.test/3",
                "published": "2026-08-02",
                "severity": "Medium",
                "confidence_score": 0.8,
                "cves": [
                    "CVE-2026-1234",
                    "invalid",
                ],
                "malware": [
                    "emotet",
                    "TrickBot",
                ],
                "mitre_techniques": [
                    "T1566",
                    "invalid",
                ],
                "apt_groups": [
                    "APT29",
                ],
                "targeted_sectors": (
                    "Healthcare"
                ),
                "affected_technologies": [],
            },
        },
    }

    def fake_otx_lookup(
        indicator,
        indicator_type,
    ):
        captured["otx_arguments"] = (
            indicator,
            indicator_type,
        )
        return otx_result

    def fake_virustotal_lookup(
        indicator,
        indicator_type,
    ):
        captured["virustotal_arguments"] = (
            indicator,
            indicator_type,
        )
        return virustotal_result

    def fake_get_article_ids(
        indicator,
        indicator_type,
    ):
        captured["repository_arguments"] = (
            indicator,
            indicator_type,
        )
        return [
            2,
            1,
            3,
        ]

    def fake_get_correlation(article_id):
        captured["article_lookups"].append(
            article_id
        )
        return correlations[article_id]

    monkeypatch.setattr(
        service,
        "lookup_otx_indicator",
        fake_otx_lookup,
    )
    monkeypatch.setattr(
        service,
        "lookup_virustotal_indicator",
        fake_virustotal_lookup,
    )
    monkeypatch.setattr(
        service,
        "get_article_ids_by_indicator",
        fake_get_article_ids,
    )
    monkeypatch.setattr(
        service,
        "get_article_correlation_data",
        fake_get_correlation,
    )

    result = correlate_indicator(
        "Example[.]COM",
        include_otx=True,
        include_virustotal=True,
    )

    assert captured["otx_arguments"] == (
        "example.com",
        "domain",
    )
    assert captured["virustotal_arguments"] == (
        "example.com",
        "domain",
    )
    assert captured["repository_arguments"] == (
        "example.com",
        "domain",
    )
    assert captured["article_lookups"] == [
        2,
        1,
        3,
    ]

    assert result["supporting_article_count"] == 3
    assert result["supporting_article_ids"] == [
        2,
        1,
        3,
    ]
    assert result["otx_enrichment"] is otx_result
    assert (
        result["virustotal_enrichment"]
        is virustotal_result
    )

    assert result["supporting_articles"] == [
        {
            "article_id": 2,
            "title": "First article",
            "link": "https://example.test/2",
            "published": "2026-08-01",
            "severity": "High",
            "confidence_score": 0.9,
        },
        {
            "article_id": 3,
            "title": "Second article",
            "link": "https://example.test/3",
            "published": "2026-08-02",
            "severity": "Medium",
            "confidence_score": 0.8,
        },
    ]

    assert result["related_entities"] == {
        "cves": [
            {
                "value": "CVE-2026-1234",
                "supporting_article_count": 2,
                "supporting_article_ids": [
                    2,
                    3,
                ],
            },
        ],
        "malware": [
            {
                "value": "Emotet",
                "supporting_article_count": 2,
                "supporting_article_ids": [
                    2,
                    3,
                ],
            },
            {
                "value": "TrickBot",
                "supporting_article_count": 1,
                "supporting_article_ids": [
                    3,
                ],
            },
        ],
        "mitre_techniques": [
            {
                "value": "T1566",
                "supporting_article_count": 2,
                "supporting_article_ids": [
                    2,
                    3,
                ],
            },
        ],
        "apt_groups": [
            {
                "value": "APT29",
                "supporting_article_count": 1,
                "supporting_article_ids": [
                    3,
                ],
            },
        ],
        "targeted_sectors": [
            {
                "value": "Finance",
                "supporting_article_count": 1,
                "supporting_article_ids": [
                    2,
                ],
            },
        ],
        "affected_technologies": [
            {
                "value": "Windows",
                "supporting_article_count": 1,
                "supporting_article_ids": [
                    2,
                ],
            },
        ],
    }