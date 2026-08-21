import pytest

import scoring.indicator_scoring_service as service
from scoring.indicator_scoring_service import (
    _build_related_cve_enrichment,
    _build_related_mitre_enrichment,
    _extract_related_values,
    _select_highest_article_severity,
    build_indicator_scoring_report,
    score_indicator,
)


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "supporting_articles",
    [
        None,
        {},
        "invalid",
        (
            {
                "severity": "High",
            },
        ),
    ],
)
def test_select_highest_article_severity_rejects_non_lists(
    supporting_articles,
):
    assert _select_highest_article_severity(
        supporting_articles
    ) is None


def test_select_highest_article_severity_ignores_invalid_entries():
    supporting_articles = [
        None,
        "invalid",
        {},
        {
            "severity": None,
        },
        {
            "severity": "unsupported",
        },
    ]

    assert _select_highest_article_severity(
        supporting_articles
    ) is None


def test_select_highest_article_severity_selects_highest():
    supporting_articles = [
        {
            "severity": "Low",
        },
        {
            "severity": "High",
        },
        {
            "severity": "Medium",
        },
        {
            "severity": "Critical",
        },
    ]

    assert _select_highest_article_severity(
        supporting_articles
    ) == "Critical"


def test_select_highest_article_severity_keeps_first_tie():
    supporting_articles = [
        {
            "severity": "HIGH",
        },
        {
            "severity": "high",
        },
    ]

    assert _select_highest_article_severity(
        supporting_articles
    ) == "HIGH"


@pytest.mark.parametrize(
    "related_entities",
    [
        None,
        [],
        "invalid",
        123,
    ],
)
def test_extract_related_values_rejects_non_dicts(
    related_entities,
):
    assert _extract_related_values(
        related_entities,
        "cves",
    ) == []


@pytest.mark.parametrize(
    "related_entities",
    [
        {},
        {
            "cves": None,
        },
        {
            "cves": "CVE-2026-1001",
        },
        {
            "cves": (
                {
                    "value": "CVE-2026-1001",
                },
            ),
        },
    ],
)
def test_extract_related_values_requires_list_field(
    related_entities,
):
    assert _extract_related_values(
        related_entities,
        "cves",
    ) == []


def test_extract_related_values_filters_invalid_entries():
    related_entities = {
        "cves": [
            None,
            "invalid",
            {},
            {
                "value": None,
            },
            {
                "value": 123,
            },
            {
                "value": "   ",
            },
            {
                "value": "CVE-2026-1001",
            },
            {
                "value": " CVE-2026-1002 ",
            },
        ],
    }

    assert _extract_related_values(
        related_entities,
        "cves",
    ) == [
        "CVE-2026-1001",
        " CVE-2026-1002 ",
    ]


def test_build_related_cve_enrichment_handles_no_values(
    monkeypatch,
):
    def unexpected_lookup(cve_id):
        raise AssertionError(
            f"Unexpected CVE lookup: {cve_id}"
        )

    monkeypatch.setattr(
        service,
        "get_cve_details",
        unexpected_lookup,
    )

    assert _build_related_cve_enrichment(
        None
    ) == []


def test_build_related_cve_enrichment_deduplicates_and_maps(
    monkeypatch,
):
    calls = []

    def fake_get_cve_details(cve_id):
        calls.append(cve_id)

        if cve_id == "CVE-2026-1001":
            return {
                "cve_id": cve_id,
                "cvss_score": 9.8,
            }

        if cve_id == "CVE-2026-1002":
            return {}

        return None

    monkeypatch.setattr(
        service,
        "get_cve_details",
        fake_get_cve_details,
    )

    related_entities = {
        "cves": [
            {
                "value": "CVE-2026-1001",
            },
            {
                "value": "CVE-2026-1001",
            },
            {
                "value": "CVE-2026-1002",
            },
            {
                "value": "CVE-2026-1003",
            },
        ],
    }

    result = _build_related_cve_enrichment(
        related_entities
    )

    assert calls == [
        "CVE-2026-1001",
        "CVE-2026-1002",
        "CVE-2026-1003",
    ]

    assert result == [
        {
            "cve_id": "CVE-2026-1001",
            "enrichment_available": True,
            "details": {
                "cve_id": "CVE-2026-1001",
                "cvss_score": 9.8,
            },
        },
        {
            "cve_id": "CVE-2026-1002",
            "enrichment_available": False,
            "details": None,
        },
        {
            "cve_id": "CVE-2026-1003",
            "enrichment_available": False,
            "details": None,
        },
    ]


def test_build_related_mitre_enrichment_handles_no_values(
    monkeypatch,
):
    def unexpected_lookup(technique_id):
        raise AssertionError(
            "Unexpected MITRE lookup: "
            f"{technique_id}"
        )

    monkeypatch.setattr(
        service,
        "get_mitre_technique_details",
        unexpected_lookup,
    )

    assert _build_related_mitre_enrichment(
        None
    ) == []


def test_build_related_mitre_enrichment_deduplicates_and_maps(
    monkeypatch,
):
    calls = []

    def fake_get_mitre_details(technique_id):
        calls.append(technique_id)

        if technique_id == "T1566":
            return {
                "technique_id": technique_id,
                "name": "Phishing",
            }

        if technique_id == "T1059":
            return {}

        return None

    monkeypatch.setattr(
        service,
        "get_mitre_technique_details",
        fake_get_mitre_details,
    )

    related_entities = {
        "mitre_techniques": [
            {
                "value": "T1566",
            },
            {
                "value": "T1566",
            },
            {
                "value": "T1059",
            },
            {
                "value": "T1190",
            },
        ],
    }

    result = _build_related_mitre_enrichment(
        related_entities
    )

    assert calls == [
        "T1566",
        "T1059",
        "T1190",
    ]

    assert result == [
        {
            "technique_id": "T1566",
            "enrichment_available": True,
            "details": {
                "technique_id": "T1566",
                "name": "Phishing",
            },
        },
        {
            "technique_id": "T1059",
            "enrichment_available": False,
            "details": None,
        },
        {
            "technique_id": "T1190",
            "enrichment_available": False,
            "details": None,
        },
    ]


@pytest.mark.parametrize(
    "correlation",
    [
        None,
        [],
        "invalid",
        123,
    ],
)
def test_build_indicator_scoring_report_requires_dictionary(
    correlation,
):
    with pytest.raises(ValueError) as error_info:
        build_indicator_scoring_report(
            correlation
        )

    assert str(error_info.value) == (
        "Indicator correlation must be a "
        "dictionary."
    )


@pytest.mark.parametrize(
    "indicator",
    [
        None,
        "",
        "   ",
        123,
    ],
)
def test_build_indicator_scoring_report_requires_indicator(
    indicator,
):
    correlation = {
        "indicator": indicator,
        "indicator_type": "IPv4",
    }

    with pytest.raises(ValueError) as error_info:
        build_indicator_scoring_report(
            correlation
        )

    assert str(error_info.value) == (
        "Indicator correlation is missing an "
        "indicator."
    )


@pytest.mark.parametrize(
    "indicator_type",
    [
        None,
        "",
        "   ",
        123,
    ],
)
def test_build_indicator_scoring_report_requires_type(
    indicator_type,
):
    correlation = {
        "indicator": "8.8.8.8",
        "indicator_type": indicator_type,
    }

    with pytest.raises(ValueError) as error_info:
        build_indicator_scoring_report(
            correlation
        )

    assert str(error_info.value) == (
        "Indicator correlation is missing an "
        "indicator type."
    )


def test_build_indicator_scoring_report_without_articles():
    correlation = {
        "indicator": " example.com ",
        "indicator_type": " domain ",
        "supporting_articles": None,
        "supporting_article_ids": [],
        "related_entities": {},
        "otx_enrichment": None,
    }

    result = build_indicator_scoring_report(
        correlation,
        cve_enrichment=[],
        mitre_enrichment=[],
    )

    assert result["target"] == {
        "entity_type": "indicator",
        "indicator": "example.com",
        "indicator_type": "domain",
    }
    assert result["scoring_version"] == "1.0"


def test_build_indicator_scoring_report_delegates_inputs(
    monkeypatch,
):
    captured = {}

    fake_scoring = {
        "scoring_version": "test",
        "warnings": [],
    }

    def fake_extract(cve_enrichment):
        captured["extracted_cves_from"] = (
            cve_enrichment
        )
        return [
            9.8,
        ]

    def fake_build(**arguments):
        captured["scoring_arguments"] = arguments
        return fake_scoring

    monkeypatch.setattr(
        service,
        "extract_cvss_scores",
        fake_extract,
    )
    monkeypatch.setattr(
        service,
        "build_scoring_report",
        fake_build,
    )

    cve_enrichment = [
        {
            "cve_id": "CVE-2026-1001",
        },
    ]
    mitre_enrichment = [
        {
            "technique_id": "T1566",
        },
    ]
    related_entities = {
        "malware": [
            {
                "value": "Emotet",
            },
        ],
        "apt_groups": [
            {
                "value": "APT29",
            },
        ],
        "mitre_techniques": [
            {
                "value": "T1566",
            },
        ],
    }
    otx_record = {
        "pulse_count": 5,
    }

    correlation = {
        "indicator": " 8.8.8.8 ",
        "indicator_type": " IPv4 ",
        "supporting_articles": [
            None,
            "invalid",
            {
                "severity": "Low",
                "confidence_score": 0.4,
            },
            {
                "severity": "High",
                "confidence_score": 0.9,
            },
            {},
        ],
        "supporting_article_ids": [
            1,
            2,
        ],
        "related_entities": related_entities,
        "otx_enrichment": otx_record,
    }

    result = build_indicator_scoring_report(
        correlation,
        cve_enrichment=cve_enrichment,
        mitre_enrichment=mitre_enrichment,
    )

    assert captured[
        "extracted_cves_from"
    ] is cve_enrichment

    assert captured["scoring_arguments"] == {
        "article_severity": "High",
        "cvss_scores": [9.8],
        "otx_record": otx_record,
        "malware": ["Emotet"],
        "apt_groups": ["APT29"],
        "mitre_techniques": ["T1566"],
        "article_ids": [1, 2],
        "ai_confidences": [
            0.4,
            0.9,
            None,
        ],
        "cve_enrichment": cve_enrichment,
        "mitre_enrichment": mitre_enrichment,
        "related_entities": related_entities,
    }

    assert result["target"] == {
        "entity_type": "indicator",
        "indicator": "8.8.8.8",
        "indicator_type": "IPv4",
    }
    assert result["scoring_version"] == "test"


def test_score_indicator_orchestrates_correlation_and_enrichment(
    monkeypatch,
):
    captured = {}

    related_entities = {
        "cves": [
            {
                "value": "CVE-2026-1001",
            },
        ],
        "mitre_techniques": [
            {
                "value": "T1566",
            },
        ],
    }

    correlation = {
        "indicator": "8.8.8.8",
        "indicator_type": "IPv4",
        "related_entities": related_entities,
    }

    cve_enrichment = [
        {
            "cve_id": "CVE-2026-1001",
        },
    ]
    mitre_enrichment = [
        {
            "technique_id": "T1566",
        },
    ]
    expected = {
        "target": {
            "indicator": "8.8.8.8",
        },
    }

    def fake_correlate(
        indicator,
        include_otx,
    ):
        captured["correlation_arguments"] = (
            indicator,
            include_otx,
        )
        return correlation

    def fake_build_cves(received_entities):
        captured["cve_entities"] = (
            received_entities
        )
        return cve_enrichment

    def fake_build_mitre(received_entities):
        captured["mitre_entities"] = (
            received_entities
        )
        return mitre_enrichment

    def fake_build_report(
        received_correlation,
        *,
        cve_enrichment,
        mitre_enrichment,
    ):
        captured["report_arguments"] = {
            "correlation": received_correlation,
            "cve_enrichment": cve_enrichment,
            "mitre_enrichment": mitre_enrichment,
        }
        return expected

    monkeypatch.setattr(
        service,
        "correlate_indicator",
        fake_correlate,
    )
    monkeypatch.setattr(
        service,
        "_build_related_cve_enrichment",
        fake_build_cves,
    )
    monkeypatch.setattr(
        service,
        "_build_related_mitre_enrichment",
        fake_build_mitre,
    )
    monkeypatch.setattr(
        service,
        "build_indicator_scoring_report",
        fake_build_report,
    )

    result = score_indicator(
        "8.8.8.8",
        include_otx=False,
    )

    assert result is expected
    assert captured[
        "correlation_arguments"
    ] == (
        "8.8.8.8",
        False,
    )
    assert captured["cve_entities"] is (
        related_entities
    )
    assert captured["mitre_entities"] is (
        related_entities
    )
    assert captured["report_arguments"] == {
        "correlation": correlation,
        "cve_enrichment": cve_enrichment,
        "mitre_enrichment": mitre_enrichment,
    }
