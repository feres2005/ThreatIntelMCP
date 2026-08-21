import pytest

from ai.analyzer import (
    REQUIRED_FIELDS,
    get_invalid_classifications,
    get_invalid_confidence_score,
    get_invalid_cves,
    get_invalid_mitre_techniques,
    get_invalid_severity,
    get_list_item_type_errors,
    get_missing_fields,
    get_type_errors,
    get_validation_errors,
)


pytestmark = pytest.mark.unit


def _valid_analysis():
    return {
        "summary": (
            "A controlled threat-intelligence "
            "summary."
        ),
        "classification": [
            "malware",
            "phishing",
        ],
        "severity": "High",
        "confidence_score": 0.85,
        "iocs": [
            "8.8.8.8",
        ],
        "cves": [
            "CVE-2026-1001",
        ],
        "malware": [
            "ControlledMalware",
        ],
        "mitre_techniques": [
            "T1566.002",
        ],
        "apt_groups": [
            "ControlledGroup",
        ],
        "targeted_sectors": [
            "Finance",
        ],
        "affected_technologies": [
            "Windows",
        ],
    }


def test_get_missing_fields_accepts_complete_analysis():
    assert get_missing_fields(
        _valid_analysis()
    ) == []


def test_get_missing_fields_preserves_required_order():
    analysis = _valid_analysis()

    del analysis["summary"]
    del analysis["cves"]
    del analysis["affected_technologies"]

    result = get_missing_fields(analysis)

    expected = [
        field
        for field in REQUIRED_FIELDS
        if field in {
            "summary",
            "cves",
            "affected_technologies",
        }
    ]

    assert result == expected


def test_get_type_errors_accepts_expected_types():
    assert get_type_errors(
        _valid_analysis()
    ) == {}


def test_get_type_errors_reports_expected_and_actual_types():
    analysis = _valid_analysis()
    analysis["summary"] = 123
    analysis["classification"] = "malware"
    analysis["confidence_score"] = None

    result = get_type_errors(analysis)

    assert result == {
        "summary": {
            "expected": "str",
            "actual": "int",
        },
        "classification": {
            "expected": "list",
            "actual": "str",
        },
        "confidence_score": {
            "expected": "int or float",
            "actual": "NoneType",
        },
    }


def test_list_item_validation_accepts_string_lists():
    assert get_list_item_type_errors(
        _valid_analysis()
    ) == {}


def test_list_item_validation_reports_positions_and_types():
    analysis = _valid_analysis()

    analysis["iocs"] = [
        "8.8.8.8",
        123,
        None,
    ]
    analysis["malware"] = [
        True,
        "ControlledMalware",
    ]

    result = get_list_item_type_errors(
        analysis
    )

    assert result == {
        "iocs": {
            "expected_item_type": "str",
            "invalid_items": [
                {
                    "index": 1,
                    "value": 123,
                    "actual_type": "int",
                },
                {
                    "index": 2,
                    "value": None,
                    "actual_type": "NoneType",
                },
            ],
        },
        "malware": {
            "expected_item_type": "str",
            "invalid_items": [
                {
                    "index": 0,
                    "value": True,
                    "actual_type": "bool",
                },
            ],
        },
    }


@pytest.mark.parametrize(
    (
        "classifications",
        "expected",
    ),
    [
        (
            [
                "malware",
                "APT",
            ],
            [],
        ),
        (
            [
                "unknown",
            ],
            [
                "unknown",
            ],
        ),
        (
            [
                "malware",
                "unknown",
                "other",
            ],
            [
                "unknown",
                "other",
            ],
        ),
    ],
)
def test_classification_validation(
    classifications,
    expected,
):
    assert get_invalid_classifications(
        classifications
    ) == expected


@pytest.mark.parametrize(
    "severity",
    [
        "Critical",
        "High",
        "Medium",
        "Low",
        "None",
    ],
)
def test_severity_validation_accepts_supported_values(
    severity,
):
    assert get_invalid_severity(
        severity
    ) is None


@pytest.mark.parametrize(
    "severity",
    [
        None,
        "critical",
        "Severe",
        1,
    ],
)
def test_severity_validation_rejects_unsupported_values(
    severity,
):
    assert get_invalid_severity(
        severity
    ) == severity


@pytest.mark.parametrize(
    "confidence_score",
    [
        0,
        0.0,
        0.5,
        1,
        1.0,
    ],
)
def test_confidence_validation_accepts_closed_range(
    confidence_score,
):
    assert get_invalid_confidence_score(
        confidence_score
    ) is None


@pytest.mark.parametrize(
    "confidence_score",
    [
        True,
        False,
        None,
        "0.5",
        -0.01,
        1.01,
    ],
)
def test_confidence_validation_rejects_invalid_values(
    confidence_score,
):
    result = get_invalid_confidence_score(
        confidence_score
    )

    assert result == confidence_score


@pytest.mark.parametrize(
    (
        "cves",
        "expected",
    ),
    [
        (
            [],
            [],
        ),
        (
            [
                "CVE-2026-1001",
                "CVE-2024-12345",
            ],
            [],
        ),
        (
            [
                "cve-2026-1001",
                "CVE-26-1001",
            ],
            [
                "cve-2026-1001",
                "CVE-26-1001",
            ],
        ),
        (
            [
                "CVE-2026-100",
                "CVE-2026-ABCD",
            ],
            [
                "CVE-2026-100",
                "CVE-2026-ABCD",
            ],
        ),
    ],
)
def test_cve_validation(
    cves,
    expected,
):
    assert get_invalid_cves(cves) == expected


@pytest.mark.parametrize(
    (
        "techniques",
        "expected",
    ),
    [
        (
            [],
            [],
        ),
        (
            [
                "T1566",
                "T1566.002",
            ],
            [],
        ),
        (
            [
                "t1566",
                "T156",
            ],
            [
                "t1566",
                "T156",
            ],
        ),
        (
            [
                "T1566.02",
                "TA0001",
            ],
            [
                "T1566.02",
                "TA0001",
            ],
        ),
    ],
)
def test_mitre_technique_validation(
    techniques,
    expected,
):
    assert get_invalid_mitre_techniques(
        techniques
    ) == expected


def test_validation_accepts_valid_analysis():
    assert get_validation_errors(
        _valid_analysis()
    ) == {}


def test_validation_returns_missing_fields_first():
    analysis = _valid_analysis()

    del analysis["summary"]
    analysis["severity"] = "Severe"

    result = get_validation_errors(
        analysis
    )

    assert result == {
        "missing_fields": [
            "summary",
        ],
    }


def test_validation_returns_root_type_errors_first():
    analysis = _valid_analysis()

    analysis["summary"] = 123
    analysis["severity"] = "Severe"

    result = get_validation_errors(
        analysis
    )

    assert result == {
        "type_errors": {
            "summary": {
                "expected": "str",
                "actual": "int",
            },
        },
    }


def test_validation_returns_item_type_errors_first():
    analysis = _valid_analysis()

    analysis["iocs"] = [
        "8.8.8.8",
        123,
    ]
    analysis["severity"] = "Severe"

    result = get_validation_errors(
        analysis
    )

    assert result == {
        "item_type_errors": {
            "iocs": {
                "expected_item_type": "str",
                "invalid_items": [
                    {
                        "index": 1,
                        "value": 123,
                        "actual_type": "int",
                    },
                ],
            },
        },
    }


def test_validation_combines_semantic_errors():
    analysis = _valid_analysis()

    analysis["classification"] = [
        "malware",
        "unknown",
    ]
    analysis["severity"] = "Severe"
    analysis["confidence_score"] = 1.5
    analysis["cves"] = [
        "CVE-2026-1001",
        "invalid-cve",
    ]
    analysis["mitre_techniques"] = [
        "T1566.002",
        "invalid-technique",
    ]

    result = get_validation_errors(
        analysis
    )

    assert result == {
        "invalid_classifications": [
            "unknown",
        ],
        "invalid_severity": "Severe",
        "invalid_confidence_score": 1.5,
        "invalid_cves": [
            "invalid-cve",
        ],
        "invalid_mitre_techniques": [
            "invalid-technique",
        ],
    }


@pytest.mark.parametrize(
    "confidence_score",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
    ],
)
def test_confidence_validation_rejects_non_finite_values(
    confidence_score,
):
    import math

    result = get_invalid_confidence_score(
        confidence_score
    )

    assert isinstance(result, float)
    assert not math.isfinite(result)
