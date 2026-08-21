import pytest

import correlation.article_investigation_service as service
from correlation.article_investigation_service import (
    _build_cve_enrichment,
    _build_mitre_enrichment,
    _summarize_text,
    get_article_investigation,
)


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "value",
    [
        None,
        123,
        [],
        {},
    ],
)
def test_summarize_text_preserves_non_strings(
    value,
):
    assert _summarize_text(
        value,
        10,
    ) == (
        value,
        False,
    )


@pytest.mark.parametrize(
    (
        "value",
        "max_length",
        "expected_text",
        "expected_truncated",
    ),
    [
        (
            "  Short\n text  ",
            20,
            "Short text",
            False,
        ),
        (
            "abcdefghij",
            10,
            "abcdefghij",
            False,
        ),
        (
            "abcdefghijk",
            10,
            "abcdefg...",
            True,
        ),
    ],
)
def test_summarize_text_normalizes_and_truncates(
    value,
    max_length,
    expected_text,
    expected_truncated,
):
    assert _summarize_text(
        value,
        max_length,
    ) == (
        expected_text,
        expected_truncated,
    )


def test_build_cve_enrichment_handles_empty_ids(
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

    assert _build_cve_enrichment([]) == []


def test_build_cve_enrichment_maps_available_and_missing(
    monkeypatch,
):
    calls = []
    long_description = "A" * 1005

    def fake_get_cve_details(cve_id):
        calls.append(cve_id)

        if cve_id == "CVE-2026-1001":
            return {
                "description": long_description,
                "cvss_score": 9.8,
                "severity": "CRITICAL",
                "published": "2026-01-01",
                "last_modified": "2026-01-02",
                "vendors": [
                    "Vendor",
                ],
                "products": [
                    "Product",
                ],
                "weaknesses": [
                    "CWE-79",
                ],
            }

        return None

    monkeypatch.setattr(
        service,
        "get_cve_details",
        fake_get_cve_details,
    )

    result = _build_cve_enrichment([
        "CVE-2026-1001",
        "CVE-2026-1002",
    ])

    assert calls == [
        "CVE-2026-1001",
        "CVE-2026-1002",
    ]

    assert result[0][
        "enrichment_available"
    ] is True
    assert result[0]["details"][
        "description_truncated"
    ] is True
    assert len(
        result[0]["details"]["description"]
    ) == 1000
    assert result[0]["details"][
        "description"
    ].endswith("...")

    assert result[0]["details"][
        "cvss_score"
    ] == 9.8
    assert result[0]["details"][
        "severity"
    ] == "CRITICAL"
    assert result[0]["details"][
        "vendors"
    ] == ["Vendor"]

    assert result[1] == {
        "cve_id": "CVE-2026-1002",
        "enrichment_available": False,
        "details": None,
    }


def test_build_mitre_enrichment_handles_empty_ids(
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

    assert _build_mitre_enrichment([]) == []


def test_build_mitre_enrichment_maps_available_and_missing(
    monkeypatch,
):
    calls = []

    def fake_get_mitre_details(technique_id):
        calls.append(technique_id)

        if technique_id == "T1566":
            return {
                "name": "Phishing",
                "domain": "enterprise-attack",
                "is_subtechnique": False,
                "platforms": [
                    "Windows",
                ],
                "kill_chain_phases": [
                    {
                        "phase_name": (
                            "initial-access"
                        ),
                    },
                ],
                "version": "2.7",
                "revoked": False,
                "deprecated": False,
            }

        return None

    monkeypatch.setattr(
        service,
        "get_mitre_technique_details",
        fake_get_mitre_details,
    )

    result = _build_mitre_enrichment([
        "T1566",
        "T1190",
    ])

    assert calls == [
        "T1566",
        "T1190",
    ]

    assert result[0] == {
        "technique_id": "T1566",
        "enrichment_available": True,
        "details": {
            "name": "Phishing",
            "domain": "enterprise-attack",
            "is_subtechnique": False,
            "platforms": [
                "Windows",
            ],
            "kill_chain_phases": [
                {
                    "phase_name": "initial-access",
                },
            ],
            "version": "2.7",
            "revoked": False,
            "deprecated": False,
        },
    }

    assert result[1] == {
        "technique_id": "T1190",
        "enrichment_available": False,
        "details": None,
    }


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
def test_get_article_investigation_rejects_invalid_ids(
    article_id,
):
    with pytest.raises(ValueError) as error_info:
        get_article_investigation(
            article_id,
            include_otx=False,
        )

    assert str(error_info.value) == (
        "Article ID must be a positive integer."
    )


def test_get_article_investigation_returns_none_when_missing(
    monkeypatch,
):
    captured = {}

    def fake_get_correlation(article_id):
        captured["article_id"] = article_id
        return None

    monkeypatch.setattr(
        service,
        "get_article_correlation_data",
        fake_get_correlation,
    )

    assert get_article_investigation(
        101,
        include_otx=False,
    ) is None

    assert captured["article_id"] == 101


def test_get_article_investigation_without_otx(
    monkeypatch,
):
    captured = {}

    typed_iocs = [
        {
            "indicator": "example.com",
            "indicator_type": "domain",
        },
        {
            "indicator": "192.0.2.10",
            "indicator_type": "IPv4",
        },
    ]

    article = {
        "article_id": 102,
        "cves": [
            " cve-2026-1001 ",
            "invalid",
            "CVE-2026-1001",
        ],
        "mitre_techniques": [
            " t1566 ",
            "invalid",
            "T1566",
        ],
    }

    correlation = {
        "article": article,
        "typed_iocs": typed_iocs,
    }

    cve_result = [
        {
            "cve_id": "CVE-2026-1001",
        },
    ]
    mitre_result = [
        {
            "technique_id": "T1566",
        },
    ]

    def fake_get_correlation(article_id):
        assert article_id == 102
        return correlation

    def fake_build_cves(cve_ids):
        captured["cve_ids"] = cve_ids
        return cve_result

    def fake_build_mitre(technique_ids):
        captured["technique_ids"] = (
            technique_ids
        )
        return mitre_result

    def unexpected_otx(iocs):
        raise AssertionError(
            "OTX lookup should be disabled."
        )

    monkeypatch.setattr(
        service,
        "get_article_correlation_data",
        fake_get_correlation,
    )
    monkeypatch.setattr(
        service,
        "_build_cve_enrichment",
        fake_build_cves,
    )
    monkeypatch.setattr(
        service,
        "_build_mitre_enrichment",
        fake_build_mitre,
    )
    monkeypatch.setattr(
        service,
        "lookup_otx_indicators",
        unexpected_otx,
    )

    result = get_article_investigation(
        102,
        include_otx=False,
    )

    assert captured["cve_ids"] == [
        "CVE-2026-1001",
    ]
    assert captured["technique_ids"] == [
        "T1566",
    ]

    assert result == {
        "article": article,
        "typed_iocs": typed_iocs,
        "ioc_enrichment": [
            {
                "indicator": "example.com",
                "indicator_type": "domain",
                "otx_enrichment": None,
            },
            {
                "indicator": "192.0.2.10",
                "indicator_type": "IPv4",
                "otx_enrichment": None,
            },
        ],
        "cve_enrichment": cve_result,
        "mitre_enrichment": mitre_result,
    }


def test_get_article_investigation_with_otx(
    monkeypatch,
):
    typed_iocs = [
        {
            "indicator": "example.com",
            "indicator_type": "domain",
        },
        {
            "indicator": "192.0.2.10",
            "indicator_type": "IPv4",
        },
    ]

    article = {
        "article_id": 103,
        "cves": [],
        "mitre_techniques": [],
    }

    otx_results = [
        {
            "pulse_count": 3,
        },
        None,
    ]

    def fake_get_correlation(article_id):
        assert article_id == 103
        return {
            "article": article,
            "typed_iocs": typed_iocs,
        }

    def fake_otx_lookup(iocs):
        assert iocs is typed_iocs
        return otx_results

    monkeypatch.setattr(
        service,
        "get_article_correlation_data",
        fake_get_correlation,
    )
    monkeypatch.setattr(
        service,
        "lookup_otx_indicators",
        fake_otx_lookup,
    )
    monkeypatch.setattr(
        service,
        "_build_cve_enrichment",
        lambda cve_ids: [],
    )
    monkeypatch.setattr(
        service,
        "_build_mitre_enrichment",
        lambda technique_ids: [],
    )

    result = get_article_investigation(
        103,
        include_otx=True,
    )

    assert result["ioc_enrichment"] == [
        {
            "indicator": "example.com",
            "indicator_type": "domain",
            "otx_enrichment": {
                "pulse_count": 3,
            },
        },
        {
            "indicator": "192.0.2.10",
            "indicator_type": "IPv4",
            "otx_enrichment": None,
        },
    ]


def test_get_article_investigation_skips_otx_for_empty_iocs(
    monkeypatch,
):
    article = {
        "article_id": 104,
        "cves": [],
        "mitre_techniques": [],
    }

    def fake_get_correlation(article_id):
        assert article_id == 104
        return {
            "article": article,
            "typed_iocs": [],
        }

    def unexpected_otx(iocs):
        raise AssertionError(
            "Empty IOC list should not call OTX."
        )

    monkeypatch.setattr(
        service,
        "get_article_correlation_data",
        fake_get_correlation,
    )
    monkeypatch.setattr(
        service,
        "lookup_otx_indicators",
        unexpected_otx,
    )
    monkeypatch.setattr(
        service,
        "_build_cve_enrichment",
        lambda cve_ids: [],
    )
    monkeypatch.setattr(
        service,
        "_build_mitre_enrichment",
        lambda technique_ids: [],
    )

    result = get_article_investigation(
        104,
        include_otx=True,
    )

    assert result["typed_iocs"] == []
    assert result["ioc_enrichment"] == []
