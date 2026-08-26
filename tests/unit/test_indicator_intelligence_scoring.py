import pytest

from scoring.indicator_intelligence_scoring import (
    build_indicator_intelligence_scoring_report,
    calculate_indicator_threat_score,
    score_virustotal_confidence,
    score_virustotal_threat,
)


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "record",
    [
        None,
        {},
        [],
        "invalid",
    ],
)
def test_virustotal_threat_handles_unavailable_record(
    record,
):
    result = score_virustotal_threat(record)

    assert result["record_available"] is False
    assert result["report_available"] is False
    assert result["points"] == 0
    assert result["maximum_points"] == 45


def test_virustotal_threat_handles_missing_report():
    result = score_virustotal_threat({
        "report_available": False,
    })

    assert result["record_available"] is True
    assert result["report_available"] is False
    assert result["statistics_valid"] is True
    assert result["points"] == 0


@pytest.mark.parametrize(
    (
        "malicious_count",
        "suspicious_count",
        "expected_points",
    ),
    [
        (0, 0, 0),
        (1, 0, 8),
        (3, 0, 15),
        (6, 0, 25),
        (12, 0, 35),
        (28, 0, 45),
        (0, 4, 15),
    ],
)
def test_virustotal_threat_scores_detection_ratio(
    malicious_count,
    suspicious_count,
    expected_points,
):
    result = score_virustotal_threat({
        "report_available": True,
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "total_engine_count": 61,
    })

    assert result["statistics_valid"] is True
    assert result["points"] == expected_points


@pytest.mark.parametrize(
    "record",
    [
        {
            "report_available": True,
            "malicious_count": "28",
            "suspicious_count": 0,
            "total_engine_count": 61,
        },
        {
            "report_available": True,
            "malicious_count": 28,
            "suspicious_count": 0,
            "total_engine_count": 0,
        },
        {
            "report_available": True,
            "malicious_count": 50,
            "suspicious_count": 20,
            "total_engine_count": 61,
        },
    ],
)
def test_virustotal_threat_rejects_invalid_statistics(
    record,
):
    result = score_virustotal_threat(record)

    assert result["statistics_valid"] is False
    assert result["points"] == 0


def test_clean_virustotal_report_is_informational():
    result = calculate_indicator_threat_score(
        virustotal_record={
            "report_available": True,
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engine_count": 61,
        }
    )

    assert result["evidence_present"] is True
    assert result["threat_score"] == 0
    assert result["threat_level"] == (
        "Informational"
    )


def test_strong_virustotal_consensus_is_high():
    result = calculate_indicator_threat_score(
        virustotal_record={
            "report_available": True,
            "malicious_count": 28,
            "suspicious_count": 0,
            "total_engine_count": 61,
        }
    )

    assert result["threat_score"] == 45
    assert result["threat_level"] == "High"


def test_cross_source_corroboration_can_be_critical():
    result = calculate_indicator_threat_score(
        virustotal_record={
            "report_available": True,
            "malicious_count": 28,
            "suspicious_count": 0,
            "total_engine_count": 61,
        },
        otx_record={
            "pulse_count": 20,
            "malware_families": ["Controlled"],
            "adversaries": ["Controlled actor"],
            "validation": [],
        },
        article_severity="High",
    )

    assert result["threat_score"] > 70
    assert result["threat_level"] == "Critical"


def test_fresh_virustotal_report_has_full_confidence_weight():
    result = score_virustotal_confidence({
        "report_available": True,
        "malicious_count": 28,
        "suspicious_count": 0,
        "total_engine_count": 61,
        "cache_status": "fresh",
    })

    assert result == {
        "record_available": True,
        "report_available": True,
        "record_points": 15,
        "engine_coverage_points": 15,
        "freshness_points": 5,
        "points": 35,
        "maximum_points": 35,
    }


def test_stale_virustotal_report_reduces_confidence_only():
    record = {
        "report_available": True,
        "malicious_count": 28,
        "suspicious_count": 0,
        "total_engine_count": 61,
        "cache_status": "stale_fallback",
        "is_stale": True,
    }

    threat = score_virustotal_threat(record)
    confidence = score_virustotal_confidence(
        record
    )

    assert threat["points"] == 45
    assert confidence["points"] == 31


def test_vendor_first_report_builds_expected_priority():
    result = (
        build_indicator_intelligence_scoring_report(
            virustotal_record={
                "report_available": True,
                "malicious_count": 28,
                "suspicious_count": 0,
                "total_engine_count": 61,
                "cache_status": "fresh",
                "is_stale": False,
            },
            otx_record=None,
            article_ids=[],
            ai_confidences=[],
            cve_enrichment=[],
            mitre_enrichment=[],
            related_entities={},
        )
    )

    assert result["scoring_version"] == "2.0"
    assert result["threat"]["threat_score"] == 45
    assert result["threat"]["threat_level"] == (
        "High"
    )
    assert result["confidence"][
        "confidence_score"
    ] == 35
    assert result["confidence"][
        "confidence_level"
    ] == "Medium"
    assert result["priority"]["priority_code"] == (
        "P2"
    )
    assert result["priority"][
        "recommended_action"
    ] == "Validate immediately"