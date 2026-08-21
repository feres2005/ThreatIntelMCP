import pytest

from scoring.enrichment_mapping import (
    extract_cvss_scores,
)


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "cve_enrichment",
    [
        None,
        {},
        "invalid",
        (
            {
                "enrichment_available": True,
                "details": {
                    "cvss_score": 9.8,
                },
            },
        ),
    ],
)
def test_extract_cvss_scores_rejects_non_lists(
    cve_enrichment,
):
    assert extract_cvss_scores(
        cve_enrichment
    ) == []


def test_extract_cvss_scores_accepts_an_empty_list():
    assert extract_cvss_scores([]) == []


def test_extract_cvss_scores_filters_invalid_entries():
    cve_enrichment = [
        None,
        "invalid-entry",
        {
            "enrichment_available": False,
            "details": {
                "cvss_score": 10.0,
            },
        },
        {
            "details": {
                "cvss_score": 8.8,
            },
        },
        {
            "enrichment_available": True,
            "details": None,
        },
        {
            "enrichment_available": True,
            "details": {},
        },
        {
            "enrichment_available": True,
            "details": {
                "cvss_score": 9.8,
            },
        },
        {
            "enrichment_available": True,
            "details": {
                "cvss_score": 0.0,
                "severity": "NONE",
            },
        },
    ]

    assert extract_cvss_scores(
        cve_enrichment
    ) == [
        9.8,
        0.0,
    ]


def test_extract_cvss_scores_preserves_source_order():
    cve_enrichment = [
        {
            "enrichment_available": True,
            "details": {
                "cvss_score": 4.2,
            },
        },
        {
            "enrichment_available": True,
            "details": {
                "cvss_score": 9.1,
            },
        },
        {
            "enrichment_available": True,
            "details": {
                "cvss_score": 7.5,
            },
        },
    ]

    assert extract_cvss_scores(
        cve_enrichment
    ) == [
        4.2,
        9.1,
        7.5,
    ]
