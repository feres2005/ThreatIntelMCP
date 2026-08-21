import math

import pytest
from scoring.threat_scoring import (
    calculate_threat_score,
    determine_threat_level,
    has_benign_otx_validation,
    normalize_article_severity,
    normalize_cvss_score,
    score_article_severity,
    score_cvss,
    score_highest_cvss,
    score_malware_and_apt,
    score_mitre_context,
    score_otx_threat,
)


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("unknown", "unknown"),
        (" Low ", "low"),
        ("MEDIUM", "medium"),
        ("High", "high"),
        (" critical ", "critical"),
        ("None", "unknown"),
        ("unsupported", "unknown"),
    ],
)
def test_normalize_article_severity(
    value,
    expected,
):
    assert normalize_article_severity(
        value
    ) == expected


@pytest.mark.parametrize(
    "value",
    [
        None,
        123,
        True,
        [],
        {},
    ],
)
def test_normalize_article_severity_rejects_non_strings(
    value,
):
    assert normalize_article_severity(
        value
    ) == "unknown"


@pytest.mark.parametrize(
    (
        "value",
        "normalized_severity",
        "expected_points",
    ),
    [
        ("unknown", "unknown", 0),
        ("low", "low", 8),
        ("medium", "medium", 15),
        ("high", "high", 22),
        ("critical", "critical", 30),
        ("None", "unknown", 0),
    ],
)
def test_score_article_severity(
    value,
    normalized_severity,
    expected_points,
):
    assert score_article_severity(value) == {
        "normalized_severity": (
            normalized_severity
        ),
        "points": expected_points,
        "maximum_points": 30,
    }


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, 0.0),
        (5, 5.0),
        (7.25, 7.25),
        (10, 10.0),
    ],
)
def test_normalize_cvss_score_accepts_valid_values(
    value,
    expected,
):
    assert normalize_cvss_score(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        False,
        "9.8",
        -0.01,
        10.01,
        math.inf,
        -math.inf,
        math.nan,
    ],
)
def test_normalize_cvss_score_rejects_invalid_values(
    value,
):
    assert normalize_cvss_score(value) is None


def test_score_cvss_returns_points_for_valid_score():
    assert score_cvss(7.25) == {
        "normalized_cvss": 7.25,
        "valid": True,
        "points": 21.75,
        "maximum_points": 30,
    }


def test_score_cvss_returns_zero_for_invalid_score():
    assert score_cvss("critical") == {
        "normalized_cvss": None,
        "valid": False,
        "points": 0,
        "maximum_points": 30,
    }


@pytest.mark.parametrize(
    "values",
    [
        None,
        [],
    ],
)
def test_score_highest_cvss_handles_no_scores(
    values,
):
    assert score_highest_cvss(values) == {
        "highest_cvss": None,
        "valid_cvss_count": 0,
        "invalid_cvss_count": 0,
        "points": 0,
        "maximum_points": 30,
    }


@pytest.mark.parametrize(
    "values",
    [
        "9.8",
        9.8,
        {"cvss": 9.8},
        {9.8},
    ],
)
def test_score_highest_cvss_rejects_invalid_collections(
    values,
):
    assert score_highest_cvss(values) == {
        "highest_cvss": None,
        "valid_cvss_count": 0,
        "invalid_cvss_count": 1,
        "points": 0,
        "maximum_points": 30,
    }


def test_score_highest_cvss_handles_mixed_values():
    result = score_highest_cvss([
        7.5,
        9.8,
        "invalid",
        True,
        math.nan,
        -1,
        11,
    ])

    assert result == {
        "highest_cvss": 9.8,
        "valid_cvss_count": 2,
        "invalid_cvss_count": 5,
        "points": 29.4,
        "maximum_points": 30,
    }


def test_score_highest_cvss_accepts_tuples():
    result = score_highest_cvss(
        (
            0,
            4.25,
            10,
        )
    )

    assert result == {
        "highest_cvss": 10.0,
        "valid_cvss_count": 3,
        "invalid_cvss_count": 0,
        "points": 30.0,
        "maximum_points": 30,
    }


@pytest.mark.parametrize(
    "validation",
    [
        None,
        {},
        "false positive",
        123,
        True,
    ],
)
def test_has_benign_otx_validation_rejects_non_lists(
    validation,
):
    assert has_benign_otx_validation(
        validation
    ) is False


@pytest.mark.parametrize(
    "entry",
    [
        {
            "name": "Known false positive",
        },
        {
            "source": "Internal_WHITELIST",
        },
        {
            "message": "Marked false-positive",
        },
        {
            "message": "Confirmed FALSE_POSITIVE",
        },
    ],
)
def test_has_benign_otx_validation_detects_markers(
    entry,
):
    assert has_benign_otx_validation([
        entry
    ]) is True


def test_has_benign_otx_validation_ignores_malformed_entries():
    validation = [
        None,
        "invalid",
        {
            "name": None,
        },
        {
            "source": 123,
        },
        {
            "message": "Suspicious indicator",
        },
    ]

    assert has_benign_otx_validation(
        validation
    ) is False


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
def test_score_otx_threat_handles_unavailable_records(
    otx_record,
):
    assert score_otx_threat(otx_record) == {
        "record_available": False,
        "pulse_count": 0,
        "pulse_count_valid": False,
        "pulse_points": 0,
        "malware_family_points": 0,
        "adversary_points": 0,
        "raw_points": 0,
        "benign_validation": False,
        "benign_override_applied": False,
        "points": 0,
        "maximum_points": 15,
    }


@pytest.mark.parametrize(
    ("pulse_count", "expected_points"),
    [
        (0, 0),
        (1, 2),
        (4, 2),
        (5, 3),
        (9, 3),
        (10, 5),
        (100, 5),
    ],
)
def test_score_otx_threat_scores_pulse_bands(
    pulse_count,
    expected_points,
):
    result = score_otx_threat({
        "pulse_count": pulse_count,
    })

    assert result["record_available"] is True
    assert result["pulse_count"] == pulse_count
    assert result["pulse_count_valid"] is True
    assert result["pulse_points"] == expected_points
    assert result["points"] == expected_points


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
def test_score_otx_threat_rejects_invalid_pulse_counts(
    pulse_count,
):
    result = score_otx_threat({
        "pulse_count": pulse_count,
    })

    assert result["pulse_count"] == 0
    assert result["pulse_count_valid"] is False
    assert result["pulse_points"] == 0


@pytest.mark.parametrize(
    (
        "malware_families",
        "adversaries",
        "expected_malware_points",
        "expected_adversary_points",
    ),
    [
        (
            [],
            [],
            0,
            0,
        ),
        (
            ["Emotet"],
            [],
            5,
            0,
        ),
        (
            [],
            ["APT29"],
            0,
            5,
        ),
        (
            [
                None,
                "",
                {},
                [],
            ],
            [
                None,
            ],
            0,
            0,
        ),
    ],
)
def test_score_otx_threat_scores_entity_evidence(
    malware_families,
    adversaries,
    expected_malware_points,
    expected_adversary_points,
):
    result = score_otx_threat({
        "pulse_count": 0,
        "malware_families": malware_families,
        "adversaries": adversaries,
    })

    assert result["malware_family_points"] == (
        expected_malware_points
    )
    assert result["adversary_points"] == (
        expected_adversary_points
    )
    assert result["points"] == (
        expected_malware_points
        + expected_adversary_points
    )


def test_score_otx_threat_combines_all_evidence():
    result = score_otx_threat({
        "pulse_count": 12,
        "malware_families": [
            "Emotet",
        ],
        "adversaries": [
            "APT29",
        ],
        "validation": [],
    })

    assert result == {
        "record_available": True,
        "pulse_count": 12,
        "pulse_count_valid": True,
        "pulse_points": 5,
        "malware_family_points": 5,
        "adversary_points": 5,
        "raw_points": 15,
        "benign_validation": False,
        "benign_override_applied": False,
        "points": 15,
        "maximum_points": 15,
    }


def test_score_otx_threat_applies_benign_override():
    result = score_otx_threat({
        "pulse_count": 12,
        "malware_families": [
            "Emotet",
        ],
        "validation": [
            {
                "message": (
                    "Confirmed false positive"
                ),
            },
        ],
    })

    assert result["raw_points"] == 10
    assert result["benign_validation"] is True
    assert result["benign_override_applied"] is True
    assert result["points"] == 0


def test_score_otx_threat_does_not_override_zero_points():
    result = score_otx_threat({
        "pulse_count": 0,
        "validation": [
            {
                "source": "Whitelist",
            },
        ],
    })

    assert result["raw_points"] == 0
    assert result["benign_validation"] is True
    assert result["benign_override_applied"] is False
    assert result["points"] == 0


@pytest.mark.parametrize(
    (
        "malware",
        "apt_groups",
        "expected",
    ),
    [
        (
            None,
            None,
            {
                "malware_count": 0,
                "apt_group_count": 0,
                "invalid_malware_count": 0,
                "invalid_apt_group_count": 0,
                "malware_points": 0,
                "apt_points": 0,
                "points": 0,
                "maximum_points": 20,
            },
        ),
        (
            "Emotet",
            {"group": "APT29"},
            {
                "malware_count": 0,
                "apt_group_count": 0,
                "invalid_malware_count": 1,
                "invalid_apt_group_count": 1,
                "malware_points": 0,
                "apt_points": 0,
                "points": 0,
                "maximum_points": 20,
            },
        ),
        (
            ["Emotet"],
            [],
            {
                "malware_count": 1,
                "apt_group_count": 0,
                "invalid_malware_count": 0,
                "invalid_apt_group_count": 0,
                "malware_points": 8,
                "apt_points": 0,
                "points": 8,
                "maximum_points": 20,
            },
        ),
        (
            [
                "Emotet",
                "TrickBot",
            ],
            [],
            {
                "malware_count": 2,
                "apt_group_count": 0,
                "invalid_malware_count": 0,
                "invalid_apt_group_count": 0,
                "malware_points": 12,
                "apt_points": 0,
                "points": 12,
                "maximum_points": 20,
            },
        ),
        (
            [],
            ["APT29"],
            {
                "malware_count": 0,
                "apt_group_count": 1,
                "invalid_malware_count": 0,
                "invalid_apt_group_count": 0,
                "malware_points": 0,
                "apt_points": 8,
                "points": 8,
                "maximum_points": 20,
            },
        ),
        (
            ["Emotet"],
            ["APT29"],
            {
                "malware_count": 1,
                "apt_group_count": 1,
                "invalid_malware_count": 0,
                "invalid_apt_group_count": 0,
                "malware_points": 8,
                "apt_points": 8,
                "points": 16,
                "maximum_points": 20,
            },
        ),
        (
            [
                "Emotet",
                "TrickBot",
                "QakBot",
            ],
            [
                "APT29",
                "Lazarus Group",
            ],
            {
                "malware_count": 3,
                "apt_group_count": 2,
                "invalid_malware_count": 0,
                "invalid_apt_group_count": 0,
                "malware_points": 12,
                "apt_points": 8,
                "points": 20,
                "maximum_points": 20,
            },
        ),
        (
            [
                " Emotet ",
                "emotet",
                "",
                None,
                123,
                "TrickBot",
            ],
            [
                " APT29 ",
                "apt29",
                " ",
                False,
            ],
            {
                "malware_count": 2,
                "apt_group_count": 1,
                "invalid_malware_count": 3,
                "invalid_apt_group_count": 2,
                "malware_points": 12,
                "apt_points": 8,
                "points": 20,
                "maximum_points": 20,
            },
        ),
    ],
)
def test_score_malware_and_apt(
    malware,
    apt_groups,
    expected,
):
    assert score_malware_and_apt(
        malware,
        apt_groups,
    ) == expected


@pytest.mark.parametrize(
    (
        "mitre_techniques",
        "expected_count",
        "expected_invalid_count",
        "expected_points",
    ),
    [
        (
            None,
            0,
            0,
            0,
        ),
        (
            "T1566",
            0,
            1,
            0,
        ),
        (
            ["T1566"],
            1,
            0,
            1,
        ),
        (
            [
                "T1566",
                "T1059",
            ],
            2,
            0,
            2,
        ),
        (
            [
                "T1566",
                "T1059",
                "T1190",
            ],
            3,
            0,
            3,
        ),
        (
            [
                "T1566",
                "T1059",
                "T1190",
                "T1105",
            ],
            4,
            0,
            3,
        ),
        (
            [
                "T1566",
                "T1059",
                "T1190",
                "T1105",
                "T1021",
            ],
            5,
            0,
            5,
        ),
        (
            [
                " t1566 ",
                "T1566",
                "invalid",
                "",
                None,
                "t1059.001",
            ],
            2,
            3,
            2,
        ),
    ],
)
def test_score_mitre_context(
    mitre_techniques,
    expected_count,
    expected_invalid_count,
    expected_points,
):
    assert score_mitre_context(
        mitre_techniques
    ) == {
        "technique_count": expected_count,
        "invalid_technique_count": (
            expected_invalid_count
        ),
        "points": expected_points,
        "maximum_points": 5,
    }


@pytest.mark.parametrize(
    (
        "score",
        "evidence_present",
        "expected_level",
    ),
    [
        (100, False, "Unknown"),
        (0, True, "Informational"),
        (14.99, True, "Informational"),
        (15, True, "Low"),
        (29.99, True, "Low"),
        (30, True, "Medium"),
        (49.99, True, "Medium"),
        (50, True, "High"),
        (74.99, True, "High"),
        (75, True, "Critical"),
        (100, True, "Critical"),
    ],
)
def test_determine_threat_level_boundaries(
    score,
    evidence_present,
    expected_level,
):
    assert determine_threat_level(
        score,
        evidence_present,
    ) == expected_level


def test_calculate_threat_score_without_evidence():
    result = calculate_threat_score()

    assert result["scoring_version"] == "1.0"
    assert result["threat_score"] == 0
    assert result["threat_level"] == "Unknown"
    assert result["evidence_present"] is False
    assert result["warnings"] == []

    assert set(result["components"]) == {
        "article_severity",
        "cvss",
        "otx",
        "malware_and_apt",
        "mitre",
    }


@pytest.mark.parametrize(
    (
        "arguments",
        "expected_score",
    ),
    [
        (
            {
                "article_severity": "Low",
            },
            8,
        ),
        (
            {
                "cvss_scores": [0.0],
            },
            0.0,
        ),
        (
            {
                "otx_record": {
                    "pulse_count": 1,
                },
            },
            2,
        ),
        (
            {
                "malware": [
                    "Emotet",
                ],
            },
            8,
        ),
        (
            {
                "apt_groups": [
                    "APT29",
                ],
            },
            8,
        ),
        (
            {
                "mitre_techniques": [
                    "T1566",
                ],
            },
            1,
        ),
        (
            {
                "otx_record": {
                    "pulse_count": 0,
                    "validation": [
                        {
                            "source": "Whitelist",
                        },
                    ],
                },
            },
            0,
        ),
    ],
)
def test_calculate_threat_score_detects_each_evidence_source(
    arguments,
    expected_score,
):
    result = calculate_threat_score(
        **arguments
    )

    assert result["evidence_present"] is True
    assert result["threat_score"] == expected_score
    assert result["threat_level"] == (
        determine_threat_level(
            expected_score,
            True,
        )
    )


def test_calculate_threat_score_reaches_maximum():
    result = calculate_threat_score(
        article_severity="Critical",
        cvss_scores=[
            10,
        ],
        otx_record={
            "pulse_count": 12,
            "malware_families": [
                "Emotet",
            ],
            "adversaries": [
                "APT29",
            ],
        },
        malware=[
            "Emotet",
            "TrickBot",
        ],
        apt_groups=[
            "APT29",
        ],
        mitre_techniques=[
            "T1566",
            "T1059",
            "T1190",
            "T1105",
            "T1021",
        ],
    )

    assert result["threat_score"] == 100
    assert result["threat_level"] == "Critical"
    assert result["evidence_present"] is True
    assert result["warnings"] == []


def test_calculate_threat_score_reports_invalid_inputs():
    result = calculate_threat_score(
        article_severity="Severe",
        cvss_scores=[
            "invalid",
        ],
        otx_record={
            "pulse_count": "invalid",
        },
        malware=[
            "",
            None,
        ],
        apt_groups=[
            123,
        ],
        mitre_techniques=[
            "invalid",
        ],
    )

    assert result["threat_score"] == 0
    assert result["threat_level"] == "Unknown"
    assert result["warnings"] == [
        (
            "Unsupported article severity was "
            "treated as unknown."
        ),
        (
            "One or more invalid CVSS values "
            "were ignored."
        ),
        (
            "Invalid OTX pulse count was "
            "treated as zero."
        ),
        (
            "One or more invalid malware values "
            "were ignored."
        ),
        (
            "One or more invalid APT group values "
            "were ignored."
        ),
        (
            "One or more invalid MITRE technique "
            "values were ignored."
        ),
    ]


def test_calculate_threat_score_warns_when_benign_override_applies():
    result = calculate_threat_score(
        otx_record={
            "pulse_count": 10,
            "validation": [
                {
                    "message": (
                        "Confirmed false positive"
                    ),
                },
            ],
        },
    )

    assert result["components"]["otx"][
        "raw_points"
    ] == 5
    assert result["threat_score"] == 0
    assert result["evidence_present"] is True
    assert result["warnings"] == [
        (
            "OTX whitelist or false-positive "
            "evidence removed the OTX threat "
            "contribution."
        ),
    ]


def test_calculate_threat_score_warns_about_benign_zero_score():
    result = calculate_threat_score(
        otx_record={
            "pulse_count": 0,
            "validation": [
                {
                    "source": "Whitelist",
                },
            ],
        },
    )

    assert result["components"]["otx"][
        "raw_points"
    ] == 0
    assert result["threat_score"] == 0
    assert result["evidence_present"] is True
    assert result["warnings"] == [
        (
            "OTX whitelist or false-positive "
            "evidence was detected."
        ),
    ]


@pytest.mark.parametrize(
    "article_severity",
    [
        None,
        "",
        "   ",
        "none",
        "None",
    ],
)
def test_calculate_threat_score_does_not_warn_for_empty_severity(
    article_severity,
):
    result = calculate_threat_score(
        article_severity=article_severity
    )

    assert result["components"][
        "article_severity"
    ]["normalized_severity"] == "unknown"
    assert result["warnings"] == []
