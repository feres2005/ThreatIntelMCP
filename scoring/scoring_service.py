from scoring.confidence_scoring import (
    calculate_confidence_score,
)
from scoring.priority import determine_priority
from scoring.threat_scoring import (
    calculate_threat_score,
)


SCORING_VERSION = "1.0"


def build_scoring_report(
    *,
    article_severity=None,
    cvss_scores=None,
    otx_record=None,
    malware=None,
    apt_groups=None,
    mitre_techniques=None,
    article_ids=None,
    ai_confidences=None,
    cve_enrichment=None,
    mitre_enrichment=None,
    related_entities=None,
):
    threat = calculate_threat_score(
        article_severity=article_severity,
        cvss_scores=cvss_scores,
        otx_record=otx_record,
        malware=malware,
        apt_groups=apt_groups,
        mitre_techniques=mitre_techniques,
    )

    confidence = calculate_confidence_score(
        article_ids=article_ids,
        ai_confidences=ai_confidences,
        otx_record=otx_record,
        cve_enrichment=cve_enrichment,
        mitre_enrichment=mitre_enrichment,
        related_entities=related_entities,
    )

    priority = determine_priority(
        threat["threat_level"],
        confidence["confidence_level"],
    )

    warnings = [
        {
            "source": "threat",
            "message": warning,
        }
        for warning in threat["warnings"]
    ]

    warnings.extend(
        {
            "source": "confidence",
            "message": warning,
        }
        for warning in confidence["warnings"]
    )

    return {
        "scoring_version": SCORING_VERSION,
        "threat": threat,
        "confidence": confidence,
        "priority": priority,
        "warnings": warnings,
    }