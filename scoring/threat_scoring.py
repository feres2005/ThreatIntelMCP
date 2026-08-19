import math
import re
from numbers import Number

ARTICLE_SEVERITY_POINTS = {
    "unknown": 0,
    "low": 8,
    "medium": 15,
    "high": 22,
    "critical": 30,
}

BENIGN_OTX_MARKERS = (
    "false positive",
    "false_positive",
    "false-positive",
    "whitelist",
)
MITRE_TECHNIQUE_PATTERN = re.compile(
    r"^T\d{4}(?:\.\d{3})?$",
    re.IGNORECASE,
)

THREAT_SCORING_VERSION = "1.0"


def normalize_article_severity(value):
    if not isinstance(value, str):
        return "unknown"

    normalized = value.strip().lower()

    if normalized in ARTICLE_SEVERITY_POINTS:
        return normalized

    return "unknown"


def score_article_severity(value):
    normalized = normalize_article_severity(value)

    return {
        "normalized_severity": normalized,
        "points": ARTICLE_SEVERITY_POINTS[normalized],
        "maximum_points": 30,
    }

def normalize_cvss_score(value):
    if isinstance(value, bool) or not isinstance(value, Number):
        return None

    numeric_value = float(value)

    if not math.isfinite(numeric_value):
        return None

    if numeric_value < 0 or numeric_value > 10:
        return None

    return numeric_value


def score_cvss(value):
    normalized = normalize_cvss_score(value)

    if normalized is None:
        return {
            "normalized_cvss": None,
            "valid": False,
            "points": 0,
            "maximum_points": 30,
        }

    return {
        "normalized_cvss": normalized,
        "valid": True,
        "points": round(normalized * 3, 2),
        "maximum_points": 30,
    }

def score_highest_cvss(values):
    if values is None:
        values = []

    if not isinstance(values, (list, tuple)):
        return {
            "highest_cvss": None,
            "valid_cvss_count": 0,
            "invalid_cvss_count": 1,
            "points": 0,
            "maximum_points": 30,
        }

    valid_scores = []
    invalid_count = 0

    for value in values:
        normalized = normalize_cvss_score(value)

        if normalized is None:
            invalid_count += 1
        else:
            valid_scores.append(normalized)

    if not valid_scores:
        return {
            "highest_cvss": None,
            "valid_cvss_count": 0,
            "invalid_cvss_count": invalid_count,
            "points": 0,
            "maximum_points": 30,
        }

    highest_cvss = max(valid_scores)

    return {
        "highest_cvss": highest_cvss,
        "valid_cvss_count": len(valid_scores),
        "invalid_cvss_count": invalid_count,
        "points": round(highest_cvss * 3, 2),
        "maximum_points": 30,
    }

def has_benign_otx_validation(validation):
    if not isinstance(validation, list):
        return False

    for entry in validation:
        if not isinstance(entry, dict):
            continue

        searchable_parts = []

        for field_name in ("name", "source", "message"):
            field_value = entry.get(field_name)

            if isinstance(field_value, str):
                searchable_parts.append(field_value.lower())

        searchable_text = " ".join(searchable_parts)

        if any(
            marker in searchable_text
            for marker in BENIGN_OTX_MARKERS
        ):
            return True

    return False

def _has_otx_entity_evidence(value):
    if not isinstance(value, list):
        return False

    return any(
        item not in (None, "", {}, [])
        for item in value
    )


def score_otx_threat(otx_record):
    if not isinstance(otx_record, dict) or not otx_record:
        return {
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

    pulse_count = otx_record.get("pulse_count")
    pulse_count_valid = (
        isinstance(pulse_count, int)
        and not isinstance(pulse_count, bool)
        and pulse_count >= 0
    )

    if not pulse_count_valid:
        pulse_count = 0

    if pulse_count == 0:
        pulse_points = 0
    elif pulse_count <= 4:
        pulse_points = 2
    elif pulse_count <= 9:
        pulse_points = 3
    else:
        pulse_points = 5

    malware_family_points = (
        5
        if _has_otx_entity_evidence(
            otx_record.get("malware_families")
        )
        else 0
    )

    adversary_points = (
        5
        if _has_otx_entity_evidence(
            otx_record.get("adversaries")
        )
        else 0
    )

    raw_points = min(
        pulse_points
        + malware_family_points
        + adversary_points,
        15,
    )

    benign_validation = has_benign_otx_validation(
        otx_record.get("validation")
    )

    final_points = 0 if benign_validation else raw_points

    return {
        "record_available": True,
        "pulse_count": pulse_count,
        "pulse_count_valid": pulse_count_valid,
        "pulse_points": pulse_points,
        "malware_family_points": malware_family_points,
        "adversary_points": adversary_points,
        "raw_points": raw_points,
        "benign_validation": benign_validation,
        "benign_override_applied": (
            benign_validation and raw_points > 0
        ),
        "points": final_points,
        "maximum_points": 15,
    }

def _normalize_entity_values(values):
    if values is None:
        return [], 0

    if not isinstance(values, list):
        return [], 1

    normalized_values = []
    seen_values = set()
    invalid_count = 0

    for value in values:
        if not isinstance(value, str):
            invalid_count += 1
            continue

        cleaned_value = value.strip()

        if not cleaned_value:
            invalid_count += 1
            continue

        identity = cleaned_value.lower()

        if identity not in seen_values:
            seen_values.add(identity)
            normalized_values.append(cleaned_value)

    return normalized_values, invalid_count


def score_malware_and_apt(malware, apt_groups):
    normalized_malware, invalid_malware_count = (
        _normalize_entity_values(malware)
    )

    normalized_apt_groups, invalid_apt_count = (
        _normalize_entity_values(apt_groups)
    )

    malware_count = len(normalized_malware)
    apt_group_count = len(normalized_apt_groups)

    if malware_count == 0:
        malware_points = 0
    elif malware_count == 1:
        malware_points = 8
    else:
        malware_points = 12

    apt_points = 8 if apt_group_count > 0 else 0

    return {
        "malware_count": malware_count,
        "apt_group_count": apt_group_count,
        "invalid_malware_count": invalid_malware_count,
        "invalid_apt_group_count": invalid_apt_count,
        "malware_points": malware_points,
        "apt_points": apt_points,
        "points": min(malware_points + apt_points, 20),
        "maximum_points": 20,
    }

def score_mitre_context(mitre_techniques):
    normalized_values, invalid_count = (
        _normalize_entity_values(mitre_techniques)
    )

    valid_techniques = []

    for value in normalized_values:
        normalized_id = value.upper()

        if MITRE_TECHNIQUE_PATTERN.fullmatch(
            normalized_id
        ):
            valid_techniques.append(normalized_id)
        else:
            invalid_count += 1

    technique_count = len(valid_techniques)

    if technique_count == 0:
        points = 0
    elif technique_count == 1:
        points = 1
    elif technique_count == 2:
        points = 2
    elif technique_count <= 4:
        points = 3
    else:
        points = 5

    return {
        "technique_count": technique_count,
        "invalid_technique_count": invalid_count,
        "points": points,
        "maximum_points": 5,
    }

def determine_threat_level(score, evidence_present):
    if not evidence_present:
        return "Unknown"

    if score < 15:
        return "Informational"

    if score < 30:
        return "Low"

    if score < 50:
        return "Medium"

    if score < 75:
        return "High"

    return "Critical"


def calculate_threat_score(
    article_severity=None,
    cvss_scores=None,
    otx_record=None,
    malware=None,
    apt_groups=None,
    mitre_techniques=None,
):
    severity_component = score_article_severity(
        article_severity
    )

    cvss_component = score_highest_cvss(
        cvss_scores
    )

    otx_component = score_otx_threat(
        otx_record
    )

    malware_apt_component = score_malware_and_apt(
        malware,
        apt_groups,
    )

    mitre_component = score_mitre_context(
        mitre_techniques
    )

    total_score = round(
        min(
            severity_component["points"]
            + cvss_component["points"]
            + otx_component["points"]
            + malware_apt_component["points"]
            + mitre_component["points"],
            100,
        ),
        2,
    )

    evidence_present = any([
        severity_component["points"] > 0,
        cvss_component["valid_cvss_count"] > 0,
        otx_component["raw_points"] > 0,
        otx_component["benign_validation"],
        malware_apt_component["malware_count"] > 0,
        malware_apt_component["apt_group_count"] > 0,
        mitre_component["technique_count"] > 0,
    ])

    warnings = []


    if (
        isinstance(article_severity, str)
        and article_severity.strip().lower()
        not in ARTICLE_SEVERITY_POINTS
        and article_severity.strip().lower()
        not in ("", "none")
    ):
        warnings.append(
            "Unsupported article severity was treated as unknown."
        )

    if cvss_component["invalid_cvss_count"] > 0:
        warnings.append(
            "One or more invalid CVSS values were ignored."
        )

    if (
        isinstance(otx_record, dict)
        and "pulse_count" in otx_record
        and not otx_component["pulse_count_valid"]
    ):
        warnings.append(
            "Invalid OTX pulse count was treated as zero."
        )

    if otx_component["benign_override_applied"]:
        warnings.append(
            "OTX whitelist or false-positive evidence "
            "removed the OTX threat contribution."
        )
    elif otx_component["benign_validation"]:
        warnings.append(
            "OTX whitelist or false-positive evidence "
            "was detected."
        )

    if (
        malware_apt_component["invalid_malware_count"]
        > 0
    ):
        warnings.append(
            "One or more invalid malware values were ignored."
        )

    if (
        malware_apt_component["invalid_apt_group_count"]
        > 0
    ):
        warnings.append(
            "One or more invalid APT group values were ignored."
        )

    if mitre_component["invalid_technique_count"] > 0:
        warnings.append(
            "One or more invalid MITRE technique values "
            "were ignored."
        )

    return {
        "scoring_version": THREAT_SCORING_VERSION,
        "threat_score": total_score,
        "threat_level": determine_threat_level(
            total_score,
            evidence_present,
        ),
        "evidence_present": evidence_present,
        "components": {
            "article_severity": severity_component,
            "cvss": cvss_component,
            "otx": otx_component,
            "malware_and_apt": malware_apt_component,
            "mitre": mitre_component,
        },
        "warnings": warnings,
    }