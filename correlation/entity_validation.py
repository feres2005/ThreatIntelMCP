import re


CVE_ID_PATTERN = re.compile(
    r"^CVE-\d{4}-\d{4,}$"
)

MITRE_TECHNIQUE_PATTERN = re.compile(
    r"^T\d{4}(?:\.\d{3})?$"
)


def normalize_entity_value(
    field_name,
    value,
):
    if not isinstance(value, str):
        return None

    cleaned_value = value.strip()

    if not cleaned_value:
        return None

    if field_name == "cves":
        cleaned_value = cleaned_value.upper()

        if CVE_ID_PATTERN.fullmatch(
            cleaned_value
        ) is None:
            return None

    if field_name == "mitre_techniques":
        cleaned_value = cleaned_value.upper()

        if MITRE_TECHNIQUE_PATTERN.fullmatch(
            cleaned_value
        ) is None:
            return None

    return cleaned_value

def normalize_entity_list(
    field_name,
    values,
):
    if not isinstance(values, list):
        return []

    normalized_values = []
    seen_values = set()

    for value in values:
        normalized_value = normalize_entity_value(
            field_name,
            value,
        )

        if normalized_value is None:
            continue

        comparison_key = normalized_value.casefold()

        if comparison_key in seen_values:
            continue

        seen_values.add(comparison_key)
        normalized_values.append(normalized_value)

    return normalized_values