import pytest

from correlation.entity_validation import (
    normalize_entity_list,
    normalize_entity_value,
)


pytestmark = pytest.mark.unit


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
def test_normalize_entity_value_rejects_non_strings(
    value,
):
    assert normalize_entity_value(
        "malware",
        value,
    ) is None


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "\t\n",
    ],
)
def test_normalize_entity_value_rejects_empty_strings(
    value,
):
    assert normalize_entity_value(
        "malware",
        value,
    ) is None


@pytest.mark.parametrize(
    ("field_name", "value", "expected"),
    [
        (
            "cves",
            " cve-2024-1234 ",
            "CVE-2024-1234",
        ),
        (
            "cves",
            "cve-2026-12345",
            "CVE-2026-12345",
        ),
        (
            "mitre_techniques",
            " t1566 ",
            "T1566",
        ),
        (
            "mitre_techniques",
            "t1566.002",
            "T1566.002",
        ),
        (
            "malware",
            " Emotet ",
            "Emotet",
        ),
        (
            "apt_groups",
            " APT29 ",
            "APT29",
        ),
    ],
)
def test_normalize_entity_value_accepts_valid_values(
    field_name,
    value,
    expected,
):
    assert normalize_entity_value(
        field_name,
        value,
    ) == expected


@pytest.mark.parametrize(
    "value",
    [
        "CVE-24-1234",
        "CVE-2024-123",
        "CVE-2024-ABC123",
        "CVE_2024_1234",
        "2024-1234",
        "CVE-2024-1234-extra",
    ],
)
def test_normalize_entity_value_rejects_invalid_cves(
    value,
):
    assert normalize_entity_value(
        "cves",
        value,
    ) is None


@pytest.mark.parametrize(
    "value",
    [
        "T123",
        "T12345",
        "T1566.01",
        "T1566.0001",
        "TA0001",
        "T1566-002",
        "technique-T1566",
    ],
)
def test_normalize_entity_value_rejects_invalid_mitre_ids(
    value,
):
    assert normalize_entity_value(
        "mitre_techniques",
        value,
    ) is None


@pytest.mark.parametrize(
    "values",
    [
        None,
        "CVE-2024-1234",
        ("CVE-2024-1234",),
        {"cve": "CVE-2024-1234"},
    ],
)
def test_normalize_entity_list_rejects_non_lists(
    values,
):
    assert normalize_entity_list(
        "cves",
        values,
    ) == []


def test_normalize_entity_list_preserves_first_generic_value():
    result = normalize_entity_list(
        "malware",
        [
            " Emotet ",
            "emotet",
            "EMOTET",
            " TrickBot ",
            "",
            None,
        ],
    )

    assert result == [
        "Emotet",
        "TrickBot",
    ]


def test_normalize_entity_list_filters_and_deduplicates_cves():
    result = normalize_entity_list(
        "cves",
        [
            " cve-2024-1234 ",
            "CVE-2024-1234",
            "invalid-cve",
            None,
            "CVE-2026-12345",
        ],
    )

    assert result == [
        "CVE-2024-1234",
        "CVE-2026-12345",
    ]


def test_normalize_entity_list_filters_and_deduplicates_mitre_ids():
    result = normalize_entity_list(
        "mitre_techniques",
        [
            " t1566 ",
            "T1566",
            "t1566.002",
            "T1566.002",
            "invalid",
            123,
        ],
    )

    assert result == [
        "T1566",
        "T1566.002",
    ]
