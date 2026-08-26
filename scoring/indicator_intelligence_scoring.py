from scoring.confidence_scoring import (
    calculate_confidence_score,
    score_otx_confidence,
)
from scoring.priority import determine_priority
from scoring.threat_scoring import (
    score_article_severity,
    score_highest_cvss,
    score_malware_and_apt,
    score_mitre_context,
    score_otx_threat,
)


INDICATOR_SCORING_VERSION = "2.0"


def _scaled_points(
    points,
    source_maximum,
    target_maximum,
):
    if source_maximum <= 0:
        return 0

    return round(
        min(
            max(points, 0)
            / source_maximum
            * target_maximum,
            target_maximum,
        ),
        2,
    )


def _nonnegative_integer(value):
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
    ):
        return None

    return value


def score_virustotal_threat(
    virustotal_record,
):
    if (
        not isinstance(virustotal_record, dict)
        or not virustotal_record
    ):
        return {
            "record_available": False,
            "report_available": False,
            "statistics_valid": False,
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engine_count": 0,
            "weighted_detection_count": 0,
            "detection_ratio": None,
            "points": 0,
            "maximum_points": 45,
        }

    report_available = virustotal_record.get(
        "report_available",
        True,
    )

    if report_available is False:
        return {
            "record_available": True,
            "report_available": False,
            "statistics_valid": True,
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engine_count": 0,
            "weighted_detection_count": 0,
            "detection_ratio": None,
            "points": 0,
            "maximum_points": 45,
        }

    malicious_count = _nonnegative_integer(
        virustotal_record.get(
            "malicious_count"
        )
    )
    suspicious_count = _nonnegative_integer(
        virustotal_record.get(
            "suspicious_count"
        )
    )
    total_engine_count = _nonnegative_integer(
        virustotal_record.get(
            "total_engine_count"
        )
    )

    statistics_valid = (
        report_available is True
        and malicious_count is not None
        and suspicious_count is not None
        and total_engine_count is not None
        and total_engine_count > 0
        and (
            malicious_count
            + suspicious_count
            <= total_engine_count
        )
    )

    if not statistics_valid:
        return {
            "record_available": True,
            "report_available": bool(
                report_available
            ),
            "statistics_valid": False,
            "malicious_count": (
                malicious_count or 0
            ),
            "suspicious_count": (
                suspicious_count or 0
            ),
            "total_engine_count": (
                total_engine_count or 0
            ),
            "weighted_detection_count": 0,
            "detection_ratio": None,
            "points": 0,
            "maximum_points": 45,
        }

    weighted_detection_count = round(
        malicious_count
        + suspicious_count * 0.5,
        2,
    )
    detection_ratio = round(
        weighted_detection_count
        / total_engine_count,
        6,
    )

    if weighted_detection_count == 0:
        points = 0
    elif detection_ratio <= 0.02:
        points = 8
    elif detection_ratio <= 0.05:
        points = 15
    elif detection_ratio <= 0.15:
        points = 25
    elif detection_ratio <= 0.30:
        points = 35
    else:
        points = 45

    return {
        "record_available": True,
        "report_available": True,
        "statistics_valid": True,
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "total_engine_count": total_engine_count,
        "weighted_detection_count": (
            weighted_detection_count
        ),
        "detection_ratio": detection_ratio,
        "points": points,
        "maximum_points": 45,
    }


def score_otx_indicator_threat(otx_record):
    original = score_otx_threat(otx_record)
    weighted_points = _scaled_points(
        original["points"],
        original["maximum_points"],
        20,
    )

    return {
        **original,
        "source_points": original["points"],
        "source_maximum_points": original[
            "maximum_points"
        ],
        "points": weighted_points,
        "maximum_points": 20,
    }


def score_local_indicator_threat(
    *,
    article_severity=None,
    cvss_scores=None,
    malware=None,
    apt_groups=None,
    mitre_techniques=None,
):
    severity = score_article_severity(
        article_severity
    )
    cvss = score_highest_cvss(cvss_scores)
    malware_apt = score_malware_and_apt(
        malware,
        apt_groups,
    )
    mitre = score_mitre_context(
        mitre_techniques
    )

    weights = {
        "article_severity": 12,
        "cvss": 12,
        "malware_and_apt": 8,
        "mitre": 3,
    }
    original_components = {
        "article_severity": severity,
        "cvss": cvss,
        "malware_and_apt": malware_apt,
        "mitre": mitre,
    }
    weighted_components = {}

    for name, component in (
        original_components.items()
    ):
        weighted_components[name] = {
            **component,
            "source_points": component["points"],
            "source_maximum_points": component[
                "maximum_points"
            ],
            "points": _scaled_points(
                component["points"],
                component["maximum_points"],
                weights[name],
            ),
            "maximum_points": weights[name],
        }

    return {
        "points": round(
            sum(
                component["points"]
                for component
                in weighted_components.values()
            ),
            2,
        ),
        "maximum_points": 35,
        "components": weighted_components,
    }


def determine_indicator_threat_level(
    score,
    evidence_present,
):
    if not evidence_present:
        return "Unknown"

    if score < 10:
        return "Informational"

    if score < 25:
        return "Low"

    if score < 45:
        return "Medium"

    if score < 70:
        return "High"

    return "Critical"


def calculate_indicator_threat_score(
    *,
    virustotal_record=None,
    otx_record=None,
    article_severity=None,
    cvss_scores=None,
    malware=None,
    apt_groups=None,
    mitre_techniques=None,
):
    virustotal = score_virustotal_threat(
        virustotal_record
    )
    otx = score_otx_indicator_threat(
        otx_record
    )
    local = score_local_indicator_threat(
        article_severity=article_severity,
        cvss_scores=cvss_scores,
        malware=malware,
        apt_groups=apt_groups,
        mitre_techniques=mitre_techniques,
    )

    total_score = round(
        min(
            virustotal["points"]
            + otx["points"]
            + local["points"],
            100,
        ),
        2,
    )
    evidence_present = any([
        virustotal["report_available"],
        otx["record_available"],
        local["points"] > 0,
    ])

    warnings = []

    if (
        virustotal["report_available"]
        and not virustotal["statistics_valid"]
    ):
        warnings.append(
            "Invalid VirusTotal analysis statistics "
            "were ignored."
        )

    if (
        isinstance(virustotal_record, dict)
        and virustotal_record.get("is_stale")
        is True
    ):
        warnings.append(
            "VirusTotal scoring used stale cached "
            "intelligence after a refresh failure."
        )

    if (
        isinstance(otx_record, dict)
        and "pulse_count" in otx_record
        and not otx["pulse_count_valid"]
    ):
        warnings.append(
            "Invalid OTX pulse count was treated "
            "as zero."
        )

    if otx["benign_override_applied"]:
        warnings.append(
            "OTX whitelist or false-positive "
            "evidence removed the OTX threat "
            "contribution."
        )

    return {
        "scoring_version": (
            INDICATOR_SCORING_VERSION
        ),
        "threat_score": total_score,
        "threat_level": (
            determine_indicator_threat_level(
                total_score,
                evidence_present,
            )
        ),
        "evidence_present": evidence_present,
        "components": {
            "virustotal": virustotal,
            "otx": otx,
            "local_corroboration": local,
        },
        "warnings": warnings,
    }


def score_virustotal_confidence(
    virustotal_record,
):
    threat_component = score_virustotal_threat(
        virustotal_record
    )

    if not threat_component["record_available"]:
        return {
            "record_available": False,
            "report_available": False,
            "record_points": 0,
            "engine_coverage_points": 0,
            "freshness_points": 0,
            "points": 0,
            "maximum_points": 35,
        }

    if not threat_component["report_available"]:
        return {
            "record_available": True,
            "report_available": False,
            "record_points": 5,
            "engine_coverage_points": 0,
            "freshness_points": 0,
            "points": 5,
            "maximum_points": 35,
        }

    record_points = 15
    engine_count = threat_component[
        "total_engine_count"
    ]

    if not threat_component["statistics_valid"]:
        engine_coverage_points = 0
    elif engine_count >= 50:
        engine_coverage_points = 15
    elif engine_count >= 20:
        engine_coverage_points = 10
    elif engine_count > 0:
        engine_coverage_points = 5
    else:
        engine_coverage_points = 0

    cache_status = (
        virustotal_record.get("cache_status")
        if isinstance(virustotal_record, dict)
        else None
    )

    if cache_status in {"fresh", "refreshed"}:
        freshness_points = 5
    elif cache_status == "stale_fallback":
        freshness_points = 1
    else:
        freshness_points = 0

    return {
        "record_available": True,
        "report_available": True,
        "record_points": record_points,
        "engine_coverage_points": (
            engine_coverage_points
        ),
        "freshness_points": freshness_points,
        "points": (
            record_points
            + engine_coverage_points
            + freshness_points
        ),
        "maximum_points": 35,
    }


def score_otx_indicator_confidence(otx_record):
    original = score_otx_confidence(otx_record)
    weighted_points = _scaled_points(
        original["points"],
        original["maximum_points"],
        25,
    )

    return {
        **original,
        "source_points": original["points"],
        "source_maximum_points": original[
            "maximum_points"
        ],
        "points": weighted_points,
        "maximum_points": 25,
    }


def score_local_indicator_confidence(
    *,
    article_ids=None,
    ai_confidences=None,
    cve_enrichment=None,
    mitre_enrichment=None,
    related_entities=None,
):
    original = calculate_confidence_score(
        article_ids=article_ids,
        ai_confidences=ai_confidences,
        otx_record=None,
        cve_enrichment=cve_enrichment,
        mitre_enrichment=mitre_enrichment,
        related_entities=related_entities,
    )

    return {
        "source_score": original[
            "confidence_score"
        ],
        "source_maximum_points": 80,
        "points": _scaled_points(
            original["confidence_score"],
            80,
            40,
        ),
        "maximum_points": 40,
        "components": original["components"],
        "warnings": original["warnings"],
    }


def calculate_indicator_confidence_score(
    *,
    virustotal_record=None,
    otx_record=None,
    article_ids=None,
    ai_confidences=None,
    cve_enrichment=None,
    mitre_enrichment=None,
    related_entities=None,
):
    virustotal = score_virustotal_confidence(
        virustotal_record
    )
    otx = score_otx_indicator_confidence(
        otx_record
    )
    local = score_local_indicator_confidence(
        article_ids=article_ids,
        ai_confidences=ai_confidences,
        cve_enrichment=cve_enrichment,
        mitre_enrichment=mitre_enrichment,
        related_entities=related_entities,
    )

    total_score = round(
        min(
            virustotal["points"]
            + otx["points"]
            + local["points"],
            100,
        ),
        2,
    )

    if total_score < 25:
        confidence_level = "Low"
    elif total_score < 50:
        confidence_level = "Medium"
    elif total_score < 75:
        confidence_level = "High"
    else:
        confidence_level = "Very High"

    warnings = list(local["warnings"])

    if (
        isinstance(virustotal_record, dict)
        and virustotal_record.get("is_stale")
        is True
    ):
        warnings.append(
            "VirusTotal confidence was reduced "
            "because stale cached intelligence "
            "was used."
        )

    return {
        "scoring_version": (
            INDICATOR_SCORING_VERSION
        ),
        "confidence_score": total_score,
        "confidence_level": confidence_level,
        "components": {
            "virustotal_corroboration": (
                virustotal
            ),
            "otx_corroboration": otx,
            "local_corroboration": local,
        },
        "warnings": warnings,
    }


def build_indicator_intelligence_scoring_report(
    *,
    virustotal_record=None,
    otx_record=None,
    article_severity=None,
    cvss_scores=None,
    malware=None,
    apt_groups=None,
    mitre_techniques=None,
    article_ids=None,
    ai_confidences=None,
    cve_enrichment=None,
    mitre_enrichment=None,
    related_entities=None,
):
    threat = calculate_indicator_threat_score(
        virustotal_record=virustotal_record,
        otx_record=otx_record,
        article_severity=article_severity,
        cvss_scores=cvss_scores,
        malware=malware,
        apt_groups=apt_groups,
        mitre_techniques=mitre_techniques,
    )
    confidence = (
        calculate_indicator_confidence_score(
            virustotal_record=(
                virustotal_record
            ),
            otx_record=otx_record,
            article_ids=article_ids,
            ai_confidences=ai_confidences,
            cve_enrichment=cve_enrichment,
            mitre_enrichment=mitre_enrichment,
            related_entities=related_entities,
        )
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
        "scoring_version": (
            INDICATOR_SCORING_VERSION
        ),
        "threat": threat,
        "confidence": confidence,
        "priority": priority,
        "warnings": warnings,
    }