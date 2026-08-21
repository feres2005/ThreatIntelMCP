import pytest

import scoring.article_scoring_service as service
from scoring.article_scoring_service import (
    _select_representative_otx,
    build_article_scoring_report,
    score_article,
)


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "investigation",
    [
        None,
        [],
        "invalid",
        123,
    ],
)
def test_build_article_scoring_report_requires_dictionary(
    investigation,
):
    with pytest.raises(ValueError) as error_info:
        build_article_scoring_report(
            investigation
        )

    assert str(error_info.value) == (
        "Article investigation must be a "
        "dictionary."
    )


@pytest.mark.parametrize(
    "investigation",
    [
        {},
        {
            "article": None,
        },
        {
            "article": [],
        },
    ],
)
def test_build_article_scoring_report_requires_article_data(
    investigation,
):
    with pytest.raises(ValueError) as error_info:
        build_article_scoring_report(
            investigation
        )

    assert str(error_info.value) == (
        "Article investigation is missing "
        "article data."
    )


@pytest.mark.parametrize(
    "article_id",
    [
        None,
        0,
        -1,
        True,
        "1",
    ],
)
def test_build_article_scoring_report_requires_valid_article_id(
    article_id,
):
    investigation = {
        "article": {
            "article_id": article_id,
        },
    }

    with pytest.raises(ValueError) as error_info:
        build_article_scoring_report(
            investigation
        )

    assert str(error_info.value) == (
        "Article scoring requires a positive "
        "integer article ID."
    )


@pytest.mark.parametrize(
    "ioc_enrichment",
    [
        None,
        {},
        "invalid",
        (
            {
                "indicator": "example.com",
            },
        ),
    ],
)
def test_select_representative_otx_rejects_non_lists(
    ioc_enrichment,
):
    assert _select_representative_otx(
        ioc_enrichment
    ) is None


def test_select_representative_otx_ignores_invalid_entries():
    ioc_enrichment = [
        None,
        "invalid",
        {},
        {
            "otx_enrichment": None,
        },
        {
            "otx_enrichment": {},
        },
        {
            "otx_enrichment": "invalid",
        },
    ]

    assert _select_representative_otx(
        ioc_enrichment
    ) is None


def test_select_representative_otx_prioritizes_threat():
    high_confidence_lower_threat = {
        "indicator": "lower.example",
        "indicator_type": "domain",
        "otx_enrichment": {
            "pulse_count": 5,
            "validation": [
                {
                    "message": (
                        "Analyst confirmed indicator"
                    ),
                },
            ],
        },
    }

    higher_threat = {
        "indicator": "higher.example",
        "indicator_type": "domain",
        "otx_enrichment": {
            "pulse_count": 10,
        },
    }

    selected = _select_representative_otx([
        high_confidence_lower_threat,
        higher_threat,
    ])

    assert selected["indicator"] == (
        "higher.example"
    )
    assert selected["threat_points"] == 5
    assert selected["confidence_points"] == 15


def test_select_representative_otx_uses_confidence_as_tiebreaker():
    lower_confidence = {
        "indicator": "first.example",
        "indicator_type": "domain",
        "otx_enrichment": {
            "pulse_count": 5,
        },
    }

    higher_confidence = {
        "indicator": "second.example",
        "indicator_type": "domain",
        "otx_enrichment": {
            "pulse_count": 5,
            "validation": [
                {
                    "source": "OTX analyst",
                },
            ],
        },
    }

    selected = _select_representative_otx([
        lower_confidence,
        higher_confidence,
    ])

    assert selected["indicator"] == (
        "second.example"
    )
    assert selected["threat_points"] == 3
    assert selected["confidence_points"] == 16


def test_select_representative_otx_keeps_first_equal_rank():
    first = {
        "indicator": "first.example",
        "indicator_type": "domain",
        "otx_enrichment": {
            "pulse_count": 5,
        },
    }

    second = {
        "indicator": "second.example",
        "indicator_type": "domain",
        "otx_enrichment": {
            "pulse_count": 5,
        },
    }

    selected = _select_representative_otx([
        first,
        second,
    ])

    assert selected["indicator"] == (
        "first.example"
    )


def test_build_article_scoring_report_without_otx():
    investigation = {
        "article": {
            "article_id": 101,
            "title": "Threat article",
            "severity": "High",
            "confidence_score": 0.8,
            "malware": [
                "Emotet",
            ],
            "apt_groups": [],
            "mitre_techniques": [
                "T1566",
            ],
        },
        "cve_enrichment": [],
        "mitre_enrichment": [],
        "ioc_enrichment": [],
    }

    result = build_article_scoring_report(
        investigation
    )

    assert result["target"] == {
        "entity_type": "article",
        "article_id": 101,
        "title": "Threat article",
    }
    assert result["otx_selection"] is None
    assert result["scoring_version"] == "1.0"


def test_build_article_scoring_report_summarizes_otx_selection():
    investigation = {
        "article": {
            "article_id": 102,
            "title": "OTX article",
            "severity": "Medium",
            "confidence_score": 0.9,
            "malware": [],
            "apt_groups": [],
            "mitre_techniques": [],
        },
        "cve_enrichment": [],
        "mitre_enrichment": [],
        "ioc_enrichment": [
            {
                "indicator": "example.com",
                "indicator_type": "domain",
                "otx_enrichment": {
                    "pulse_count": 10,
                },
            },
        ],
    }

    result = build_article_scoring_report(
        investigation
    )

    assert result["otx_selection"] == {
        "indicator": "example.com",
        "indicator_type": "domain",
        "selection_method": (
            "highest_threat_then_confidence"
        ),
        "threat_points": 5,
        "confidence_points": 15,
    }


def test_build_article_scoring_report_delegates_inputs(
    monkeypatch,
):
    captured = {}

    selected_otx = {
        "indicator": "example.com",
        "indicator_type": "domain",
        "otx_record": {
            "pulse_count": 4,
        },
        "threat_points": 2,
        "confidence_points": 8,
    }

    fake_scoring = {
        "scoring_version": "test",
        "warnings": [],
    }

    def fake_select(ioc_enrichment):
        captured["ioc_enrichment"] = (
            ioc_enrichment
        )
        return selected_otx

    def fake_extract(cve_enrichment):
        captured["cve_enrichment"] = (
            cve_enrichment
        )
        return [
            8.8,
        ]

    def fake_build(**arguments):
        captured["scoring_arguments"] = arguments
        return fake_scoring

    monkeypatch.setattr(
        service,
        "_select_representative_otx",
        fake_select,
    )
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
    ioc_enrichment = [
        {
            "indicator": "example.com",
        },
    ]

    investigation = {
        "article": {
            "article_id": 103,
            "title": "Delegation article",
            "severity": "Critical",
            "confidence_score": 0.95,
            "malware": [
                "Emotet",
            ],
            "apt_groups": [
                "APT29",
            ],
            "mitre_techniques": [
                "T1566",
            ],
        },
        "cve_enrichment": cve_enrichment,
        "mitre_enrichment": mitre_enrichment,
        "ioc_enrichment": ioc_enrichment,
    }

    result = build_article_scoring_report(
        investigation
    )

    assert captured["ioc_enrichment"] is (
        ioc_enrichment
    )
    assert captured["cve_enrichment"] is (
        cve_enrichment
    )

    assert captured["scoring_arguments"] == {
        "article_severity": "Critical",
        "cvss_scores": [8.8],
        "malware": ["Emotet"],
        "apt_groups": ["APT29"],
        "mitre_techniques": ["T1566"],
        "article_ids": [103],
        "ai_confidences": [0.95],
        "cve_enrichment": cve_enrichment,
        "mitre_enrichment": mitre_enrichment,
        "otx_record": {
            "pulse_count": 4,
        },
    }

    assert result["target"]["article_id"] == 103
    assert result["scoring_version"] == "test"


def test_score_article_returns_none_when_not_found(
    monkeypatch,
):
    captured = {}

    def fake_investigation(
        article_id,
        include_otx,
    ):
        captured["arguments"] = (
            article_id,
            include_otx,
        )
        return None

    monkeypatch.setattr(
        service,
        "get_article_investigation",
        fake_investigation,
    )

    assert score_article(
        999,
        include_otx=False,
    ) is None

    assert captured["arguments"] == (
        999,
        False,
    )


def test_score_article_builds_found_investigation(
    monkeypatch,
):
    investigation = {
        "article": {
            "article_id": 104,
        },
    }
    expected = {
        "target": {
            "article_id": 104,
        },
    }
    captured = {}

    def fake_investigation(
        article_id,
        include_otx,
    ):
        captured["investigation_arguments"] = (
            article_id,
            include_otx,
        )
        return investigation

    def fake_build(received_investigation):
        captured["received_investigation"] = (
            received_investigation
        )
        return expected

    monkeypatch.setattr(
        service,
        "get_article_investigation",
        fake_investigation,
    )
    monkeypatch.setattr(
        service,
        "build_article_scoring_report",
        fake_build,
    )

    result = score_article(
        104,
        include_otx=True,
    )

    assert result is expected
    assert captured[
        "investigation_arguments"
    ] == (
        104,
        True,
    )
    assert captured[
        "received_investigation"
    ] is investigation
