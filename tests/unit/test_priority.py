import pytest

from scoring.priority import determine_priority


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    (
        "threat_level",
        "confidence_level",
        "expected",
    ),
    [
        (
            "Unknown",
            "Low",
            {
                "threat_level": "Unknown",
                "confidence_level": "Low",
                "priority_code": "P4",
                "priority_label": "Low",
                "recommended_action": (
                    "Gather intelligence"
                ),
            },
        ),
        (
            "Informational",
            "Medium",
            {
                "threat_level": "Informational",
                "confidence_level": "Medium",
                "priority_code": "P5",
                "priority_label": "Informational",
                "recommended_action": (
                    "No immediate action"
                ),
            },
        ),
        (
            "Informational",
            "High",
            {
                "threat_level": "Informational",
                "confidence_level": "High",
                "priority_code": "P5",
                "priority_label": "Informational",
                "recommended_action": "Monitor",
            },
        ),
        (
            "Low",
            "Low",
            {
                "threat_level": "Low",
                "confidence_level": "Low",
                "priority_code": "P4",
                "priority_label": "Low",
                "recommended_action": (
                    "Collect more evidence"
                ),
            },
        ),
        (
            "Low",
            "Very High",
            {
                "threat_level": "Low",
                "confidence_level": "Very High",
                "priority_code": "P4",
                "priority_label": "Low",
                "recommended_action": "Monitor",
            },
        ),
        (
            "Medium",
            "Medium",
            {
                "threat_level": "Medium",
                "confidence_level": "Medium",
                "priority_code": "P3",
                "priority_label": "Moderate",
                "recommended_action": (
                    "Collect more evidence"
                ),
            },
        ),
        (
            "Medium",
            "High",
            {
                "threat_level": "Medium",
                "confidence_level": "High",
                "priority_code": "P2",
                "priority_label": "High",
                "recommended_action": "Investigate",
            },
        ),
        (
            " high ",
            " low ",
            {
                "threat_level": "High",
                "confidence_level": "Low",
                "priority_code": "P2",
                "priority_label": "High",
                "recommended_action": (
                    "Validate immediately"
                ),
            },
        ),
        (
            "HIGH",
            " VERY HIGH ",
            {
                "threat_level": "High",
                "confidence_level": "Very High",
                "priority_code": "P1",
                "priority_label": "Urgent",
                "recommended_action": (
                    "Urgent investigation"
                ),
            },
        ),
        (
            "Critical",
            "Medium",
            {
                "threat_level": "Critical",
                "confidence_level": "Medium",
                "priority_code": "P2",
                "priority_label": "High",
                "recommended_action": (
                    "Validate immediately"
                ),
            },
        ),
        (
            "Critical",
            "High",
            {
                "threat_level": "Critical",
                "confidence_level": "High",
                "priority_code": "P1",
                "priority_label": "Urgent",
                "recommended_action": (
                    "Urgent investigation"
                ),
            },
        ),
    ],
)
def test_determine_priority_matrix(
    threat_level,
    confidence_level,
    expected,
):
    assert determine_priority(
        threat_level,
        confidence_level,
    ) == expected


@pytest.mark.parametrize(
    (
        "threat_level",
        "confidence_level",
        "expected_message",
    ),
    [
        (
            None,
            "Low",
            "Threat level must be a string.",
        ),
        (
            "Severe",
            "Low",
            "Unsupported threat level: Severe",
        ),
        (
            "High",
            None,
            "Confidence level must be a string.",
        ),
        (
            "High",
            "Certain",
            (
                "Unsupported confidence level: "
                "Certain"
            ),
        ),
    ],
)
def test_determine_priority_rejects_invalid_levels(
    threat_level,
    confidence_level,
    expected_message,
):
    with pytest.raises(ValueError) as error_info:
        determine_priority(
            threat_level,
            confidence_level,
        )

    assert str(error_info.value) == expected_message