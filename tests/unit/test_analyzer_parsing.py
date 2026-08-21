from types import SimpleNamespace

import pytest

from ai.analyzer import (
    REQUIRED_FIELDS,
    apply_python_defaults,
    clean_json_response,
    extract_claude_text,
    parse_analysis_json,
    try_parse_analysis_json,
    try_parse_and_validate_analysis,
)


pytestmark = pytest.mark.unit


def _valid_analysis():
    return {
        "summary": "Controlled summary.",
        "classification": [
            "malware",
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
        "apt_groups": [],
        "targeted_sectors": [
            "Finance",
        ],
        "affected_technologies": [
            "Windows",
        ],
    }


def test_defaults_leave_valid_analysis_unchanged():
    analysis = _valid_analysis()
    original = {
        key: (
            list(value)
            if isinstance(value, list)
            else value
        )
        for key, value in analysis.items()
    }

    result = apply_python_defaults(
        analysis,
        {},
    )

    assert result is analysis
    assert result == original


def test_defaults_replace_invalid_semantic_values():
    analysis = _valid_analysis()

    analysis["classification"] = [
        "malware",
        "unsupported",
    ]
    analysis["severity"] = "Severe"
    analysis["confidence_score"] = 5
    analysis["cves"] = [
        "CVE-2026-1001",
        "invalid-cve",
    ]
    analysis["mitre_techniques"] = [
        "T1566.002",
        "invalid-technique",
    ]

    validation_errors = {
        "invalid_classifications": [
            "unsupported",
        ],
        "invalid_severity": "Severe",
        "invalid_confidence_score": 5,
        "invalid_cves": [
            "invalid-cve",
        ],
        "invalid_mitre_techniques": [
            "invalid-technique",
        ],
    }

    result = apply_python_defaults(
        analysis,
        validation_errors,
    )

    assert result is analysis
    assert result["classification"] == [
        "malware",
    ]
    assert result["severity"] == "None"
    assert result["confidence_score"] == 0.0
    assert result["cves"] == [
        "CVE-2026-1001",
    ]
    assert result["mitre_techniques"] == [
        "T1566.002",
    ]


def test_defaults_create_every_missing_field():
    analysis = {}

    result = apply_python_defaults(
        analysis,
        {
            "missing_fields": list(
                REQUIRED_FIELDS
            ),
        },
    )

    assert result is analysis
    assert result == {
        "summary": "",
        "classification": [],
        "severity": "None",
        "confidence_score": 0.0,
        "iocs": [],
        "cves": [],
        "malware": [],
        "mitre_techniques": [],
        "apt_groups": [],
        "targeted_sectors": [],
        "affected_technologies": [],
    }


@pytest.mark.parametrize(
    (
        "raw_text",
        "expected",
    ),
    [
        (
            '  {"status": "valid"}  ',
            '{"status": "valid"}',
        ),
        (
            (
                "```json\n"
                '{"status": "valid"}'
                "\n```"
            ),
            '{"status": "valid"}',
        ),
        (
            (
                "```\n"
                '{"status": "valid"}'
                "\n```"
            ),
            '{"status": "valid"}',
        ),
    ],
)
def test_clean_json_response_removes_fences(
    raw_text,
    expected,
):
    assert clean_json_response(
        raw_text
    ) == expected


def test_parse_analysis_json_returns_decoded_value():
    result = parse_analysis_json(
        (
            "```json\n"
            '{"severity": "High"}'
            "\n```"
        )
    )

    assert result == {
        "severity": "High",
    }


def test_try_parse_analysis_json_returns_valid_data():
    assert try_parse_analysis_json(
        '{"value": 42}'
    ) == {
        "value": 42,
    }


def test_try_parse_analysis_json_handles_invalid_json(
    caplog,
):
    result = try_parse_analysis_json(
        "{invalid-json"
    )

    assert result is None
    assert (
        "claude returned invalid JSON"
        in caplog.text
    )


def test_parse_and_validate_reports_invalid_json():
    analysis, errors = (
        try_parse_and_validate_analysis(
            "{invalid-json"
        )
    )

    assert analysis is None
    assert errors == {
        "invalid_json": (
            "Claude response could not be "
            "parsed as JSON"
        ),
    }


@pytest.mark.parametrize(
    (
        "raw_text",
        "expected_data",
        "expected_type",
    ),
    [
        (
            "[1, 2]",
            [
                1,
                2,
            ],
            "list",
        ),
        (
            '"text response"',
            "text response",
            "str",
        ),
    ],
)
def test_parse_and_validate_rejects_non_object_root(
    raw_text,
    expected_data,
    expected_type,
):
    analysis, errors = (
        try_parse_and_validate_analysis(
            raw_text
        )
    )

    assert analysis == expected_data
    assert errors == {
        "invalid_root_type": expected_type,
    }


def test_parse_and_validate_accepts_valid_analysis():
    analysis = _valid_analysis()

    import json

    parsed, errors = (
        try_parse_and_validate_analysis(
            json.dumps(analysis)
        )
    )

    assert parsed == analysis
    assert errors == {}


def test_parse_and_validate_returns_semantic_errors():
    analysis = _valid_analysis()

    analysis["severity"] = "Severe"
    analysis["cves"] = [
        "invalid-cve",
    ]

    import json

    parsed, errors = (
        try_parse_and_validate_analysis(
            json.dumps(analysis)
        )
    )

    assert parsed == analysis
    assert errors == {
        "invalid_severity": "Severe",
        "invalid_cves": [
            "invalid-cve",
        ],
    }


def test_extract_claude_text_handles_empty_response(
    caplog,
):
    response = SimpleNamespace(
        content=[],
    )

    assert extract_claude_text(
        response
    ) is None

    assert (
        "claude returned an empty response"
        in caplog.text
    )


def test_extract_claude_text_rejects_non_text_block(
    caplog,
):
    response = SimpleNamespace(
        content=[
            SimpleNamespace(
                type="tool_use",
                text=None,
            ),
        ],
    )

    assert extract_claude_text(
        response
    ) is None

    assert (
        "unexpected content block type"
        in caplog.text
    )


def test_extract_claude_text_returns_first_text_block():
    response = SimpleNamespace(
        content=[
            SimpleNamespace(
                type="text",
                text='{"status": "valid"}',
            ),
            SimpleNamespace(
                type="text",
                text="ignored second block",
            ),
        ],
    )

    assert extract_claude_text(
        response
    ) == '{"status": "valid"}'


def test_defaults_ignore_unknown_missing_field():
    analysis = {}

    result = apply_python_defaults(
        analysis,
        {
            "missing_fields": [
                "unknown_field",
            ],
        },
    )

    assert result is analysis
    assert result == {}
