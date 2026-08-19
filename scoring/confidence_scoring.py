import math
from numbers import Number

SUPPORTING_ARTICLE_POINTS = {
    0: 0,
    1: 15,
    2: 20,
    3: 24,
    4: 27,
}

AGREEMENT_FIELDS = (
    "cves",
    "malware",
    "mitre_techniques",
    "apt_groups",
)

CONFIDENCE_SCORING_VERSION = "1.0"



def score_supporting_articles(article_ids):
    if article_ids is None:
        article_ids = []

    if not isinstance(article_ids, (list, tuple)):
        return {
            "supporting_article_ids": [],
            "supporting_article_count": 0,
            "invalid_article_id_count": 1,
            "points": 0,
            "maximum_points": 30,
        }

    valid_ids = []
    seen_ids = set()
    invalid_count = 0

    for article_id in article_ids:
        is_valid = (
            isinstance(article_id, int)
            and not isinstance(article_id, bool)
            and article_id > 0
        )

        if not is_valid:
            invalid_count += 1
            continue

        if article_id not in seen_ids:
            seen_ids.add(article_id)
            valid_ids.append(article_id)

    article_count = len(valid_ids)

    if article_count >= 5:
        points = 30
    else:
        points = SUPPORTING_ARTICLE_POINTS[
            article_count
        ]

    return {
        "supporting_article_ids": valid_ids,
        "supporting_article_count": article_count,
        "invalid_article_id_count": invalid_count,
        "points": points,
        "maximum_points": 30,
    }

def normalize_ai_confidence(value):
    if isinstance(value, bool) or not isinstance(
        value,
        Number,
    ):
        return None, False

    numeric_value = float(value)

    if not math.isfinite(numeric_value):
        return None, False

    clamped_value = min(
        max(numeric_value, 0.0),
        1.0,
    )

    return (
        clamped_value,
        clamped_value != numeric_value,
    )


def score_ai_confidence(values):
    if values is None:
        values = []

    if not isinstance(values, (list, tuple)):
        return {
            "normalized_confidences": [],
            "average_confidence": None,
            "valid_confidence_count": 0,
            "invalid_confidence_count": 1,
            "clamped_confidence_count": 0,
            "points": 0,
            "maximum_points": 25,
        }

    normalized_values = []
    invalid_count = 0
    clamped_count = 0

    for value in values:
        normalized, was_clamped = (
            normalize_ai_confidence(value)
        )

        if normalized is None:
            invalid_count += 1
            continue

        normalized_values.append(normalized)

        if was_clamped:
            clamped_count += 1

    if not normalized_values:
        average_confidence = None
        points = 0
    else:
        average_confidence = round(
            sum(normalized_values)
            / len(normalized_values),
            4,
        )

        points = round(
            average_confidence * 25,
            2,
        )

    return {
        "normalized_confidences": normalized_values,
        "average_confidence": average_confidence,
        "valid_confidence_count": len(
            normalized_values
        ),
        "invalid_confidence_count": invalid_count,
        "clamped_confidence_count": clamped_count,
        "points": points,
        "maximum_points": 25,
    }

def _inspect_otx_validations(validation):
    if validation is None:
        return 0, 0

    if not isinstance(validation, list):
        return 0, 1

    valid_count = 0
    invalid_count = 0

    for entry in validation:
        if not isinstance(entry, dict):
            invalid_count += 1
            continue

        has_text = any(
            isinstance(entry.get(field_name), str)
            and bool(entry[field_name].strip())
            for field_name in (
                "name",
                "source",
                "message",
            )
        )

        if has_text:
            valid_count += 1
        else:
            invalid_count += 1

    return valid_count, invalid_count


def score_otx_confidence(otx_record):
    if not isinstance(otx_record, dict) or not otx_record:
        return {
            "record_available": False,
            "record_points": 0,
            "pulse_count": 0,
            "pulse_count_valid": False,
            "pulse_points": 0,
            "validation_count": 0,
            "invalid_validation_count": 0,
            "validation_points": 0,
            "points": 0,
            "maximum_points": 20,
        }

    record_points = 5

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
        pulse_points = 3
    elif pulse_count <= 9:
        pulse_points = 6
    else:
        pulse_points = 10

    validation_count, invalid_validation_count = (
        _inspect_otx_validations(
            otx_record.get("validation")
        )
    )

    validation_points = (
        5 if validation_count > 0 else 0
    )

    return {
        "record_available": True,
        "record_points": record_points,
        "pulse_count": pulse_count,
        "pulse_count_valid": pulse_count_valid,
        "pulse_points": pulse_points,
        "validation_count": validation_count,
        "invalid_validation_count": (
            invalid_validation_count
        ),
        "validation_points": validation_points,
        "points": min(
            record_points
            + pulse_points
            + validation_points,
            20,
        ),
        "maximum_points": 20,
    }

def _inspect_enrichment_entries(
    entries,
    identifier_field,
):
    if entries is None:
        return 0, 0, 0

    if not isinstance(entries, list):
        return 0, 0, 1

    available_count = 0
    unavailable_count = 0
    invalid_count = 0

    for entry in entries:
        if not isinstance(entry, dict):
            invalid_count += 1
            continue

        identifier = entry.get(identifier_field)
        enrichment_available = entry.get(
            "enrichment_available"
        )

        valid_identifier = (
            isinstance(identifier, str)
            and bool(identifier.strip())
        )

        if (
            not valid_identifier
            or not isinstance(
                enrichment_available,
                bool,
            )
        ):
            invalid_count += 1
            continue

        if enrichment_available:
            details = entry.get("details")

            if isinstance(details, dict) and details:
                available_count += 1
            else:
                invalid_count += 1
        else:
            unavailable_count += 1

    return (
        available_count,
        unavailable_count,
        invalid_count,
    )


def score_structured_enrichment(
    cve_enrichment,
    mitre_enrichment,
):
    (
        available_cve_count,
        unavailable_cve_count,
        invalid_cve_count,
    ) = _inspect_enrichment_entries(
        cve_enrichment,
        "cve_id",
    )

    (
        available_mitre_count,
        unavailable_mitre_count,
        invalid_mitre_count,
    ) = _inspect_enrichment_entries(
        mitre_enrichment,
        "technique_id",
    )

    cve_points = (
        10 if available_cve_count > 0 else 0
    )

    mitre_points = (
        5 if available_mitre_count > 0 else 0
    )

    return {
        "available_cve_count": available_cve_count,
        "unavailable_cve_count": (
            unavailable_cve_count
        ),
        "invalid_cve_count": invalid_cve_count,
        "available_mitre_count": (
            available_mitre_count
        ),
        "unavailable_mitre_count": (
            unavailable_mitre_count
        ),
        "invalid_mitre_count": invalid_mitre_count,
        "cve_points": cve_points,
        "mitre_points": mitre_points,
        "points": cve_points + mitre_points,
        "maximum_points": 15,
    }

def _count_repeated_entities(entries):
    if entries is None:
        return 0, 0

    if not isinstance(entries, list):
        return 0, 1

    repeated_values = set()
    invalid_count = 0

    for entry in entries:
        if not isinstance(entry, dict):
            invalid_count += 1
            continue

        value = entry.get("value")
        article_ids = entry.get(
            "supporting_article_ids"
        )

        if (
            not isinstance(value, str)
            or not value.strip()
            or not isinstance(article_ids, list)
        ):
            invalid_count += 1
            continue

        valid_article_ids = set()
        entry_has_invalid_id = False

        for article_id in article_ids:
            is_valid = (
                isinstance(article_id, int)
                and not isinstance(article_id, bool)
                and article_id > 0
            )

            if is_valid:
                valid_article_ids.add(article_id)
            else:
                entry_has_invalid_id = True

        if entry_has_invalid_id:
            invalid_count += 1

        if len(valid_article_ids) >= 2:
            repeated_values.add(
                value.strip().lower()
            )

    return len(repeated_values), invalid_count


def score_cross_article_agreement(
    related_entities,
):
    if related_entities is None:
        related_entities = {}

    if not isinstance(related_entities, dict):
        return {
            "category_results": {},
            "categories_with_agreement": [],
            "agreement_category_count": 0,
            "repeated_entity_count": 0,
            "invalid_entry_count": 1,
            "points": 0,
            "maximum_points": 10,
        }

    category_results = {}
    categories_with_agreement = []
    repeated_entity_count = 0
    invalid_entry_count = 0

    for field_name in AGREEMENT_FIELDS:
        repeated_count, invalid_count = (
            _count_repeated_entities(
                related_entities.get(field_name)
            )
        )

        category_results[field_name] = {
            "repeated_entity_count": repeated_count,
            "invalid_entry_count": invalid_count,
        }

        repeated_entity_count += repeated_count
        invalid_entry_count += invalid_count

        if repeated_count > 0:
            categories_with_agreement.append(
                field_name
            )

    agreement_category_count = len(
        categories_with_agreement
    )

    if agreement_category_count == 0:
        points = 0
    elif agreement_category_count == 1:
        points = 5
    else:
        points = 10

    return {
        "category_results": category_results,
        "categories_with_agreement": (
            categories_with_agreement
        ),
        "agreement_category_count": (
            agreement_category_count
        ),
        "repeated_entity_count": (
            repeated_entity_count
        ),
        "invalid_entry_count": invalid_entry_count,
        "points": points,
        "maximum_points": 10,
    }

def determine_confidence_level(score):
    if score < 25:
        return "Low"

    if score < 50:
        return "Medium"

    if score < 75:
        return "High"

    return "Very High"


def calculate_confidence_score(
    article_ids=None,
    ai_confidences=None,
    otx_record=None,
    cve_enrichment=None,
    mitre_enrichment=None,
    related_entities=None,
):
    article_component = score_supporting_articles(
        article_ids
    )

    ai_component = score_ai_confidence(
        ai_confidences
    )

    otx_component = score_otx_confidence(
        otx_record
    )

    enrichment_component = (
        score_structured_enrichment(
            cve_enrichment,
            mitre_enrichment,
        )
    )

    agreement_component = (
        score_cross_article_agreement(
            related_entities
        )
    )

    total_score = round(
        min(
            article_component["points"]
            + ai_component["points"]
            + otx_component["points"]
            + enrichment_component["points"]
            + agreement_component["points"],
            100,
        ),
        2,
    )

    warnings = []

    if article_component["invalid_article_id_count"] > 0:
        warnings.append(
            "One or more invalid supporting article "
            "IDs were ignored."
        )

    if ai_component["invalid_confidence_count"] > 0:
        warnings.append(
            "One or more invalid AI confidence "
            "values were ignored."
        )

    if ai_component["clamped_confidence_count"] > 0:
        warnings.append(
            "One or more AI confidence values were "
            "clamped to the range 0 to 1."
        )

    if (
        isinstance(otx_record, dict)
        and "pulse_count" in otx_record
        and not otx_component["pulse_count_valid"]
    ):
        warnings.append(
            "Invalid OTX pulse count was treated "
            "as zero."
        )

    if otx_component["invalid_validation_count"] > 0:
        warnings.append(
            "One or more invalid OTX validation "
            "entries were ignored."
        )

    if enrichment_component["invalid_cve_count"] > 0:
        warnings.append(
            "One or more invalid CVE enrichment "
            "entries were ignored."
        )

    if (
        enrichment_component["invalid_mitre_count"]
        > 0
    ):
        warnings.append(
            "One or more invalid MITRE enrichment "
            "entries were ignored."
        )

    if agreement_component["invalid_entry_count"] > 0:
        warnings.append(
            "One or more invalid cross-article "
            "agreement entries were ignored."
        )

    return {
        "scoring_version": (
            CONFIDENCE_SCORING_VERSION
        ),
        "confidence_score": total_score,
        "confidence_level": (
            determine_confidence_level(total_score)
        ),
        "components": {
            "supporting_articles": article_component,
            "ai_confidence": ai_component,
            "otx_corroboration": otx_component,
            "structured_enrichment": (
                enrichment_component
            ),
            "cross_article_agreement": (
                agreement_component
            ),
        },
        "warnings": warnings,
    }