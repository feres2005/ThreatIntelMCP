import pytest

import scoring.scoring_service as scoring_service
from scoring.scoring_service import (
    build_scoring_report,
)


pytestmark = pytest.mark.unit


def test_build_scoring_report_without_evidence():
    result = build_scoring_report()

    assert result["scoring_version"] == "1.0"

    assert result["threat"][
        "threat_score"
    ] == 0
    assert result["threat"][
        "threat_level"
    ] == "Unknown"

    assert result["confidence"][
        "confidence_score"
    ] == 0
    assert result["confidence"][
        "confidence_level"
    ] == "Low"

    assert result["priority"] == {
        "threat_level": "Unknown",
        "confidence_level": "Low",
        "priority_code": "P4",
        "priority_label": "Low",
        "recommended_action": (
            "Gather intelligence"
        ),
    }

    assert result["warnings"] == []


def test_build_scoring_report_combines_strong_evidence():
    result = build_scoring_report(
        article_severity="Critical",
        cvss_scores=[
            10,
        ],
        otx_record={
            "pulse_count": 10,
            "validation": [
                {
                    "source": "OTX analyst",
                },
            ],
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
        cve_enrichment=[
            {
                "cve_id": "CVE-2026-1001",
                "enrichment_available": True,
                "details": {
                    "cvss_score": 10,
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
                        2,
                    ],
                },
            ],
        },
    )

    assert result["threat"][
        "threat_level"
    ] == "Critical"
    assert result["confidence"][
        "confidence_level"
    ] == "Very High"

    assert result["priority"][
        "priority_code"
    ] == "P1"
    assert result["priority"][
        "recommended_action"
    ] == "Urgent investigation"

    assert result["warnings"] == []


def test_build_scoring_report_delegates_and_tags_warnings(
    monkeypatch,
):
    captured = {}

    fake_threat = {
        "threat_level": "High",
        "warnings": [
            "Threat warning",
        ],
    }

    fake_confidence = {
        "confidence_level": "Medium",
        "warnings": [
            "First confidence warning",
            "Second confidence warning",
        ],
    }

    fake_priority = {
        "priority_code": "P2",
        "priority_label": "High",
    }

    def fake_calculate_threat_score(**arguments):
        captured["threat_arguments"] = arguments
        return fake_threat

    def fake_calculate_confidence_score(
        **arguments,
    ):
        captured["confidence_arguments"] = (
            arguments
        )
        return fake_confidence

    def fake_determine_priority(
        threat_level,
        confidence_level,
    ):
        captured["priority_arguments"] = (
            threat_level,
            confidence_level,
        )
        return fake_priority

    monkeypatch.setattr(
        scoring_service,
        "calculate_threat_score",
        fake_calculate_threat_score,
    )
    monkeypatch.setattr(
        scoring_service,
        "calculate_confidence_score",
        fake_calculate_confidence_score,
    )
    monkeypatch.setattr(
        scoring_service,
        "determine_priority",
        fake_determine_priority,
    )

    result = build_scoring_report(
        article_severity="High",
        cvss_scores=[8.8],
        otx_record={
            "pulse_count": 3,
        },
        malware=["Emotet"],
        apt_groups=["APT29"],
        mitre_techniques=["T1566"],
        article_ids=[10, 20],
        ai_confidences=[0.8],
        cve_enrichment=["cve-data"],
        mitre_enrichment=["mitre-data"],
        related_entities={
            "cves": [],
        },
    )

    assert captured["threat_arguments"] == {
        "article_severity": "High",
        "cvss_scores": [8.8],
        "otx_record": {
            "pulse_count": 3,
        },
        "malware": ["Emotet"],
        "apt_groups": ["APT29"],
        "mitre_techniques": ["T1566"],
    }

    assert captured[
        "confidence_arguments"
    ] == {
        "article_ids": [10, 20],
        "ai_confidences": [0.8],
        "otx_record": {
            "pulse_count": 3,
        },
        "cve_enrichment": ["cve-data"],
        "mitre_enrichment": ["mitre-data"],
        "related_entities": {
            "cves": [],
        },
    }

    assert captured["priority_arguments"] == (
        "High",
        "Medium",
    )

    assert result == {
        "scoring_version": "1.0",
        "threat": fake_threat,
        "confidence": fake_confidence,
        "priority": fake_priority,
        "warnings": [
            {
                "source": "threat",
                "message": "Threat warning",
            },
            {
                "source": "confidence",
                "message": (
                    "First confidence warning"
                ),
            },
            {
                "source": "confidence",
                "message": (
                    "Second confidence warning"
                ),
            },
        ],
    }
