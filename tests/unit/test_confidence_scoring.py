import math

import pytest

from scoring.confidence_scoring import (
    _count_repeated_entities,
    _inspect_enrichment_entries,
    _inspect_otx_validations,
    calculate_confidence_score,
    determine_confidence_level,
    normalize_ai_confidence,
    score_ai_confidence,
    score_cross_article_agreement,
    score_otx_confidence,
    score_structured_enrichment,
    score_supporting_articles,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "article_ids",
    [
        "1",
        1,
        {"article_id": 1},
        {1, 2},
    ],
)
def test_score_supporting_articles_rejects_invalid_collections(
    article_ids,
):
    assert score_supporting_articles(
        article_ids
    ) == {
        "supporting_article_ids": [],
        "supporting_article_count": 0,
        "invalid_article_id_count": 1,
        "points": 0,
        "maximum_points": 30,
    }


@pytest.mark.parametrize(
    (
        "article_ids",
        "expected_ids",
        "expected_invalid_count",
        "expected_points",
    ),
    [
        (
            [],
            [],
            0,
            0,
        ),
        (
            [1],
            [1],
            0,
            15,
        ),
        (
            [1, 2],
            [1, 2],
            0,
            20,
        ),
        (
            [1, 2, 3],
            [1, 2, 3],
            0,
            24,
        ),
        (
            [1, 2, 3, 4],
            [1, 2, 3, 4],
            0,
            27,
        ),
        (
            [1, 2, 3, 4, 5],
            [1, 2, 3, 4, 5],
            0,
            30,
        ),
        (
            (1, 2, 3, 4, 5, 6),
            [1, 2, 3, 4, 5, 6],
            0,
            30,
        ),
        (
            [
                1,
                1,
                2,
                0,
                -1,
                True,
                "3",
                None,
            ],
            [1, 2],
            5,
            20,
        ),
    ],
)
def test_score_supporting_articles(
    article_ids,
    expected_ids,
    expected_invalid_count,
    expected_points,
):
    assert score_supporting_articles(
        article_ids
    ) == {
        "supporting_article_ids": expected_ids,
        "supporting_article_count": len(
            expected_ids
        ),
        "invalid_article_id_count": (
            expected_invalid_count
        ),
        "points": expected_points,
        "maximum_points": 30,
    }


@pytest.mark.parametrize(
    (
        "value",
        "expected_value",
        "expected_clamped",
    ),
    [
        (0, 0.0, False),
        (0.4, 0.4, False),
        (1, 1.0, False),
        (-0.2, 0.0, True),
        (1.2, 1.0, True),
    ],
)
def test_normalize_ai_confidence(
    value,
    expected_value,
    expected_clamped,
):
    assert normalize_ai_confidence(value) == (
        expected_value,
        expected_clamped,
    )


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        False,
        "0.8",
        [],
        math.nan,
        math.inf,
        -math.inf,
    ],
)
def test_normalize_ai_confidence_rejects_invalid_values(
    value,
):
    assert normalize_ai_confidence(value) == (
        None,
        False,
    )


@pytest.mark.parametrize(
    "values",
    [
        None,
        [],
    ],
)
def test_score_ai_confidence_handles_no_values(
    values,
):
    assert score_ai_confidence(values) == {
        "normalized_confidences": [],
        "average_confidence": None,
        "valid_confidence_count": 0,
        "invalid_confidence_count": 0,
        "clamped_confidence_count": 0,
        "points": 0,
        "maximum_points": 25,
    }


@pytest.mark.parametrize(
    "values",
    [
        0.8,
        "0.8",
        {},
        {0.8},
    ],
)
def test_score_ai_confidence_rejects_invalid_collections(
    values,
):
    assert score_ai_confidence(values) == {
        "normalized_confidences": [],
        "average_confidence": None,
        "valid_confidence_count": 0,
        "invalid_confidence_count": 1,
        "clamped_confidence_count": 0,
        "points": 0,
        "maximum_points": 25,
    }


def test_score_ai_confidence_handles_all_invalid_values():
    assert score_ai_confidence([
        None,
        True,
        "0.8",
        math.nan,
    ]) == {
        "normalized_confidences": [],
        "average_confidence": None,
        "valid_confidence_count": 0,
        "invalid_confidence_count": 4,
        "clamped_confidence_count": 0,
        "points": 0,
        "maximum_points": 25,
    }


def test_score_ai_confidence_normalizes_mixed_values():
    result = score_ai_confidence([
        0.2,
        0.8,
        -1,
        2,
        "invalid",
        True,
        math.nan,
    ])

    assert result == {
        "normalized_confidences": [
            0.2,
            0.8,
            0.0,
            1.0,
        ],
        "average_confidence": 0.5,
        "valid_confidence_count": 4,
        "invalid_confidence_count": 3,
        "clamped_confidence_count": 2,
        "points": 12.5,
        "maximum_points": 25,
    }


def test_score_ai_confidence_accepts_tuples():
    result = score_ai_confidence(
        (
            0.3333,
            0.6667,
        )
    )

    assert result == {
        "normalized_confidences": [
            0.3333,
            0.6667,
        ],
        "average_confidence": 0.5,
        "valid_confidence_count": 2,
        "invalid_confidence_count": 0,
        "clamped_confidence_count": 0,
        "points": 12.5,
        "maximum_points": 25,
    }


def test_inspect_otx_validations_handles_missing_value():
    assert _inspect_otx_validations(
        None
    ) == (
        0,
        0,
    )


@pytest.mark.parametrize(
    "validation",
    [
        {},
        "validation",
        123,
    ],
)
def test_inspect_otx_validations_rejects_non_lists(
    validation,
):
    assert _inspect_otx_validations(
        validation
    ) == (
        0,
        1,
    )


def test_inspect_otx_validations_counts_entries():
    validation = [
        None,
        "invalid",
        {},
        {
            "name": "   ",
        },
        {
            "name": 123,
        },
        {
            "name": "Analyst validation",
        },
        {
            "name": " ",
            "source": "OTX",
        },
        {
            "message": "Confirmed indicator",
        },
    ]

    assert _inspect_otx_validations(
        validation
    ) == (
        3,
        5,
    )


@pytest.mark.parametrize(
    "otx_record",
    [
        None,
        {},
        [],
        "",
        0,
    ],
)
def test_score_otx_confidence_handles_unavailable_records(
    otx_record,
):
    assert score_otx_confidence(
        otx_record
    ) == {
        "record_available": False,
        "record_points": 0,
        "pulse_count": 0,
        "pulse_count_valid": False,
        "pulse_points": 0,
        "validation_count": 0,
        "invalid_validation_count": 0,
        "validation_points": 0,
        "points": 0,
        "maximum_points": 20,
    }


@pytest.mark.parametrize(
    (
        "pulse_count",
        "expected_pulse_points",
    ),
    [
        (0, 0),
        (1, 3),
        (4, 3),
        (5, 6),
        (9, 6),
        (10, 10),
        (100, 10),
    ],
)
def test_score_otx_confidence_scores_pulse_bands(
    pulse_count,
    expected_pulse_points,
):
    result = score_otx_confidence({
        "pulse_count": pulse_count,
    })

    assert result["record_available"] is True
    assert result["record_points"] == 5
    assert result["pulse_count"] == pulse_count
    assert result["pulse_count_valid"] is True
    assert result["pulse_points"] == (
        expected_pulse_points
    )
    assert result["points"] == (
        5 + expected_pulse_points
    )


@pytest.mark.parametrize(
    "pulse_count",
    [
        None,
        True,
        False,
        -1,
        "5",
        5.0,
    ],
)
def test_score_otx_confidence_rejects_invalid_pulse_counts(
    pulse_count,
):
    result = score_otx_confidence({
        "pulse_count": pulse_count,
    })

    assert result["record_available"] is True
    assert result["pulse_count"] == 0
    assert result["pulse_count_valid"] is False
    assert result["pulse_points"] == 0
    assert result["points"] == 5


def test_score_otx_confidence_adds_validation_points():
    result = score_otx_confidence({
        "pulse_count": 10,
        "validation": [
            {
                "source": "OTX analyst",
            },
        ],
    })

    assert result == {
        "record_available": True,
        "record_points": 5,
        "pulse_count": 10,
        "pulse_count_valid": True,
        "pulse_points": 10,
        "validation_count": 1,
        "invalid_validation_count": 0,
        "validation_points": 5,
        "points": 20,
        "maximum_points": 20,
    }


def test_score_otx_confidence_reports_invalid_validation():
    result = score_otx_confidence({
        "pulse_count": 0,
        "validation": "invalid",
    })

    assert result["validation_count"] == 0
    assert result["invalid_validation_count"] == 1
    assert result["validation_points"] == 0
    assert result["points"] == 5


def test_inspect_enrichment_entries_handles_missing_value():
    assert _inspect_enrichment_entries(
        None,
        "cve_id",
    ) == (
        0,
        0,
        0,
    )


@pytest.mark.parametrize(
    "entries",
    [
        {},
        "invalid",
        123,
        (
            {
                "cve_id": "CVE-2026-1234",
            },
        ),
    ],
)
def test_inspect_enrichment_entries_rejects_non_lists(
    entries,
):
    assert _inspect_enrichment_entries(
        entries,
        "cve_id",
    ) == (
        0,
        0,
        1,
    )


def test_inspect_enrichment_entries_classifies_entries():
    entries = [
        None,
        {
            "cve_id": None,
            "enrichment_available": True,
            "details": {
                "cvss_score": 9.8,
            },
        },
        {
            "cve_id": "   ",
            "enrichment_available": True,
            "details": {
                "cvss_score": 9.8,
            },
        },
        {
            "cve_id": "CVE-2026-1001",
            "enrichment_available": "true",
            "details": {
                "cvss_score": 9.8,
            },
        },
        {
            "cve_id": "CVE-2026-1002",
            "enrichment_available": True,
            "details": None,
        },
        {
            "cve_id": "CVE-2026-1003",
            "enrichment_available": True,
            "details": {},
        },
        {
            "cve_id": "CVE-2026-1004",
            "enrichment_available": True,
            "details": {
                "cvss_score": 9.8,
            },
        },
        {
            "cve_id": "CVE-2026-1005",
            "enrichment_available": False,
            "details": None,
        },
    ]

    assert _inspect_enrichment_entries(
        entries,
        "cve_id",
    ) == (
        1,
        1,
        6,
    )


@pytest.mark.parametrize(
    (
        "cve_enrichment",
        "mitre_enrichment",
        "expected_cve_points",
        "expected_mitre_points",
        "expected_total_points",
    ),
    [
        (
            None,
            None,
            0,
            0,
            0,
        ),
        (
            [
                {
                    "cve_id": "CVE-2026-1001",
                    "enrichment_available": True,
                    "details": {
                        "cvss_score": 9.8,
                    },
                },
            ],
            None,
            10,
            0,
            10,
        ),
        (
            None,
            [
                {
                    "technique_id": "T1566",
                    "enrichment_available": True,
                    "details": {
                        "name": "Phishing",
                    },
                },
            ],
            0,
            5,
            5,
        ),
        (
            [
                {
                    "cve_id": "CVE-2026-1001",
                    "enrichment_available": True,
                    "details": {
                        "cvss_score": 9.8,
                    },
                },
            ],
            [
                {
                    "technique_id": "T1566",
                    "enrichment_available": True,
                    "details": {
                        "name": "Phishing",
                    },
                },
            ],
            10,
            5,
            15,
        ),
        (
            [
                {
                    "cve_id": "CVE-2026-1001",
                    "enrichment_available": False,
                },
            ],
            [
                {
                    "technique_id": "T1566",
                    "enrichment_available": False,
                },
            ],
            0,
            0,
            0,
        ),
    ],
)
def test_score_structured_enrichment_points(
    cve_enrichment,
    mitre_enrichment,
    expected_cve_points,
    expected_mitre_points,
    expected_total_points,
):
    result = score_structured_enrichment(
        cve_enrichment,
        mitre_enrichment,
    )

    assert result["cve_points"] == (
        expected_cve_points
    )
    assert result["mitre_points"] == (
        expected_mitre_points
    )
    assert result["points"] == (
        expected_total_points
    )
    assert result["maximum_points"] == 15


def test_score_structured_enrichment_reports_invalid_collections():
    result = score_structured_enrichment(
        "invalid-cve-data",
        {"technique": "T1566"},
    )

    assert result == {
        "available_cve_count": 0,
        "unavailable_cve_count": 0,
        "invalid_cve_count": 1,
        "available_mitre_count": 0,
        "unavailable_mitre_count": 0,
        "invalid_mitre_count": 1,
        "cve_points": 0,
        "mitre_points": 0,
        "points": 0,
        "maximum_points": 15,
    }


def test_count_repeated_entities_handles_missing_value():
    assert _count_repeated_entities(
        None
    ) == (
        0,
        0,
    )


@pytest.mark.parametrize(
    "entries",
    [
        {},
        "invalid",
        (
            {
                "value": "Emotet",
                "supporting_article_ids": [1, 2],
            },
        ),
    ],
)
def test_count_repeated_entities_rejects_non_lists(
    entries,
):
    assert _count_repeated_entities(
        entries
    ) == (
        0,
        1,
    )


def test_count_repeated_entities_normalizes_and_validates():
    entries = [
        None,
        {
            "value": None,
            "supporting_article_ids": [
                1,
                2,
            ],
        },
        {
            "value": "   ",
            "supporting_article_ids": [
                1,
                2,
            ],
        },
        {
            "value": "Emotet",
            "supporting_article_ids": "1,2",
        },
        {
            "value": "Emotet",
            "supporting_article_ids": [
                1,
                2,
            ],
        },
        {
            "value": "emotet",
            "supporting_article_ids": [
                3,
                4,
            ],
        },
        {
            "value": "APT29",
            "supporting_article_ids": [
                1,
                1,
            ],
        },
        {
            "value": "T1566",
            "supporting_article_ids": [
                1,
                2,
                0,
                True,
            ],
        },
    ]

    assert _count_repeated_entities(
        entries
    ) == (
        2,
        5,
    )


def test_score_cross_article_agreement_handles_missing_data():
    result = score_cross_article_agreement(
        None
    )

    assert result["categories_with_agreement"] == []
    assert result["agreement_category_count"] == 0
    assert result["repeated_entity_count"] == 0
    assert result["invalid_entry_count"] == 0
    assert result["points"] == 0

    assert set(result["category_results"]) == {
        "cves",
        "malware",
        "mitre_techniques",
        "apt_groups",
    }


@pytest.mark.parametrize(
    "related_entities",
    [
        [],
        "invalid",
        123,
    ],
)
def test_score_cross_article_agreement_rejects_non_dicts(
    related_entities,
):
    assert score_cross_article_agreement(
        related_entities
    ) == {
        "category_results": {},
        "categories_with_agreement": [],
        "agreement_category_count": 0,
        "repeated_entity_count": 0,
        "invalid_entry_count": 1,
        "points": 0,
        "maximum_points": 10,
    }


def test_score_cross_article_agreement_scores_one_category():
    result = score_cross_article_agreement({
        "cves": [
            {
                "value": "CVE-2026-1001",
                "supporting_article_ids": [
                    1,
                    2,
                ],
            },
        ],
    })

    assert result["categories_with_agreement"] == [
        "cves",
    ]
    assert result["agreement_category_count"] == 1
    assert result["repeated_entity_count"] == 1
    assert result["invalid_entry_count"] == 0
    assert result["points"] == 5


def test_score_cross_article_agreement_scores_multiple_categories():
    result = score_cross_article_agreement({
        "cves": [
            {
                "value": "CVE-2026-1001",
                "supporting_article_ids": [
                    1,
                    2,
                ],
            },
            {
                "value": "CVE-2026-1002",
                "supporting_article_ids": [
                    2,
                    3,
                ],
            },
        ],
        "malware": [
            {
                "value": "Emotet",
                "supporting_article_ids": [
                    1,
                    3,
                ],
            },
        ],
    })

    assert result["categories_with_agreement"] == [
        "cves",
        "malware",
    ]
    assert result["agreement_category_count"] == 2
    assert result["repeated_entity_count"] == 3
    assert result["invalid_entry_count"] == 0
    assert result["points"] == 10
    assert result["maximum_points"] == 10


def test_score_cross_article_agreement_reports_invalid_entries():
    result = score_cross_article_agreement({
        "cves": "invalid",
        "malware": [
            None,
        ],
    })

    assert result["agreement_category_count"] == 0
    assert result["repeated_entity_count"] == 0
    assert result["invalid_entry_count"] == 2
    assert result["points"] == 0


@pytest.mark.parametrize(
    (
        "score",
        "expected_level",
    ),
    [
        (0, "Low"),
        (24.99, "Low"),
        (25, "Medium"),
        (49.99, "Medium"),
        (50, "High"),
        (74.99, "High"),
        (75, "Very High"),
        (100, "Very High"),
    ],
)
def test_determine_confidence_level_boundaries(
    score,
    expected_level,
):
    assert determine_confidence_level(
        score
    ) == expected_level


def test_calculate_confidence_score_without_evidence():
    result = calculate_confidence_score()

    assert result["scoring_version"] == "1.0"
    assert result["confidence_score"] == 0
    assert result["confidence_level"] == "Low"
    assert result["warnings"] == []

    assert set(result["components"]) == {
        "supporting_articles",
        "ai_confidence",
        "otx_corroboration",
        "structured_enrichment",
        "cross_article_agreement",
    }


def test_calculate_confidence_score_reaches_maximum():
    result = calculate_confidence_score(
        article_ids=[
            1,
            2,
            3,
            4,
            5,
        ],
        ai_confidences=[
            1.0,
        ],
        otx_record={
            "pulse_count": 10,
            "validation": [
                {
                    "source": "OTX analyst",
                },
            ],
        },
        cve_enrichment=[
            {
                "cve_id": "CVE-2026-1001",
                "enrichment_available": True,
                "details": {
                    "cvss_score": 9.8,
                },
            },
        ],
        mitre_enrichment=[
            {
                "technique_id": "T1566",
                "enrichment_available": True,
                "details": {
                    "name": "Phishing",
                },
            },
        ],
        related_entities={
            "cves": [
                {
                    "value": "CVE-2026-1001",
                    "supporting_article_ids": [
                        1,
                        2,
                    ],
                },
            ],
            "malware": [
                {
                    "value": "Emotet",
                    "supporting_article_ids": [
                        1,
                        3,
                    ],
                },
            ],
        },
    )

    assert result["confidence_score"] == 100
    assert result["confidence_level"] == (
        "Very High"
    )
    assert result["warnings"] == []


def test_calculate_confidence_score_reports_invalid_inputs():
    result = calculate_confidence_score(
        article_ids=[
            0,
        ],
        ai_confidences=[
            math.nan,
            -1,
            2,
        ],
        otx_record={
            "pulse_count": "invalid",
            "validation": [
                "invalid",
            ],
        },
        cve_enrichment="invalid",
        mitre_enrichment={},
        related_entities="invalid",
    )

    assert result["warnings"] == [
        (
            "One or more invalid supporting article "
            "IDs were ignored."
        ),
        (
            "One or more invalid AI confidence "
            "values were ignored."
        ),
        (
            "One or more AI confidence values were "
            "clamped to the range 0 to 1."
        ),
        (
            "Invalid OTX pulse count was treated "
            "as zero."
        ),
        (
            "One or more invalid OTX validation "
            "entries were ignored."
        ),
        (
            "One or more invalid CVE enrichment "
            "entries were ignored."
        ),
        (
            "One or more invalid MITRE enrichment "
            "entries were ignored."
        ),
        (
            "One or more invalid cross-article "
            "agreement entries were ignored."
        ),
    ]
