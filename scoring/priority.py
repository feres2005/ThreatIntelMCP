VALID_THREAT_LEVELS = {
    "unknown": "Unknown",
    "informational": "Informational",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}

VALID_CONFIDENCE_LEVELS = {
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "very high": "Very High",
}


def _normalize_level(value, allowed_levels, label):
    if not isinstance(value, str):
        raise ValueError(
            f"{label} level must be a string."
        )

    normalized = value.strip().lower()

    if normalized not in allowed_levels:
        raise ValueError(
            f"Unsupported {label.lower()} level: "
            f"{value}"
        )

    return allowed_levels[normalized]


def determine_priority(
    threat_level,
    confidence_level,
):
    threat = _normalize_level(
        threat_level,
        VALID_THREAT_LEVELS,
        "Threat",
    )

    confidence = _normalize_level(
        confidence_level,
        VALID_CONFIDENCE_LEVELS,
        "Confidence",
    )

    strong_confidence = confidence in {
        "High",
        "Very High",
    }

    if threat == "Unknown":
        result = (
            "P4",
            "Low",
            "Gather intelligence",
        )
    elif threat == "Informational":
        result = (
            "P5",
            "Informational",
            (
                "Monitor"
                if strong_confidence
                else "No immediate action"
            ),
        )
    elif threat == "Low":
        result = (
            "P4",
            "Low",
            (
                "Monitor"
                if strong_confidence
                else "Collect more evidence"
            ),
        )
    elif threat == "Medium":
        result = (
            (
                "P2",
                "High",
                "Investigate",
            )
            if strong_confidence
            else (
                "P3",
                "Moderate",
                "Collect more evidence",
            )
        )
    else:
        result = (
            (
                "P1",
                "Urgent",
                "Urgent investigation",
            )
            if strong_confidence
            else (
                "P2",
                "High",
                "Validate immediately",
            )
        )

    priority_code, priority_label, action = result

    return {
        "threat_level": threat,
        "confidence_level": confidence,
        "priority_code": priority_code,
        "priority_label": priority_label,
        "recommended_action": action,
    }