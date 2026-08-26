import base64
from datetime import datetime, timezone
import os
from urllib.parse import quote

from dotenv import load_dotenv
import requests


load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv(
    "VIRUSTOTAL_API_KEY"
)
VIRUSTOTAL_API_BASE_URL = (
    "https://www.virustotal.com/api/v3"
)
VIRUSTOTAL_TIMEOUT_SECONDS = 20

VIRUSTOTAL_RESOURCE_NAMES = {
    "IPv4": "ip_addresses",
    "IPv6": "ip_addresses",
    "domain": "domains",
    "URL": "urls",
    "FileHash-MD5": "files",
    "FileHash-SHA1": "files",
    "FileHash-SHA256": "files",
}

ANALYSIS_STAT_FIELDS = {
    "malicious": "malicious_count",
    "suspicious": "suspicious_count",
    "harmless": "harmless_count",
    "undetected": "undetected_count",
    "timeout": "timeout_count",
    "failure": "failure_count",
    "type-unsupported": (
        "type_unsupported_count"
    ),
    "confirmed-timeout": (
        "confirmed_timeout_count"
    ),
}

VIRUSTOTAL_GUI_RESOURCE_NAMES = {
    "file": "file",
    "ip_address": "ip-address",
    "domain": "domain",
    "url": "url",
}


def _encode_url_identifier(url):
    return base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("ascii").rstrip("=")


def get_virustotal_resource_path(
    indicator,
    indicator_type,
):
    if not isinstance(indicator, str):
        raise ValueError(
            "VirusTotal indicator must be a string."
        )

    normalized_indicator = indicator.strip()

    if not normalized_indicator:
        raise ValueError(
            "VirusTotal indicator cannot be empty."
        )

    try:
        resource_name = (
            VIRUSTOTAL_RESOURCE_NAMES[
                indicator_type
            ]
        )
    except KeyError as error:
        raise ValueError(
            "Unsupported VirusTotal indicator type: "
            f"{indicator_type}"
        ) from error

    resource_identifier = (
        _encode_url_identifier(
            normalized_indicator
        )
        if indicator_type == "URL"
        else normalized_indicator
    )

    return (
        f"{resource_name}/"
        f"{quote(resource_identifier, safe='')}"
    )


def fetch_virustotal_indicator(
    indicator,
    indicator_type,
):
    if not VIRUSTOTAL_API_KEY:
        raise ValueError(
            "VIRUSTOTAL_API_KEY was not found "
            "in the .env file."
        )

    resource_path = get_virustotal_resource_path(
        indicator,
        indicator_type,
    )

    response = requests.get(
        (
            f"{VIRUSTOTAL_API_BASE_URL}/"
            f"{resource_path}"
        ),
        headers={
            "x-apikey": VIRUSTOTAL_API_KEY,
        },
        timeout=VIRUSTOTAL_TIMEOUT_SECONDS,
    )

    if response.status_code == 404:
        return None

    response.raise_for_status()

    return response.json()


def _normalize_nonnegative_integer(value):
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
    ):
        return 0

    return value


def _normalize_analysis_stats(attributes):
    raw_stats = attributes.get(
        "last_analysis_stats"
    )

    if not isinstance(raw_stats, dict):
        raw_stats = {}

    normalized = {
        normalized_name: (
            _normalize_nonnegative_integer(
                raw_stats.get(raw_name)
            )
        )
        for raw_name, normalized_name
        in ANALYSIS_STAT_FIELDS.items()
    }

    normalized["total_result_count"] = sum(
        normalized.values()
    )
    normalized["total_engine_count"] = sum(
        normalized[field_name]
        for field_name in (
            "malicious_count",
            "suspicious_count",
            "harmless_count",
            "undetected_count",
        )
    )
    return normalized


def _normalize_string_list(value):
    if not isinstance(value, list):
        return []

    normalized = []
    seen = set()

    for entry in value:
        if not isinstance(entry, str):
            continue

        cleaned = entry.strip()

        if not cleaned:
            continue

        identity = cleaned.casefold()

        if identity not in seen:
            seen.add(identity)
            normalized.append(cleaned)

    return normalized


def _normalize_categories(value):
    if isinstance(value, dict):
        return _normalize_string_list(
            list(value.values())
        )

    return _normalize_string_list(value)


def _normalize_detections(value):
    if not isinstance(value, dict):
        return []

    detections = []

    for engine_key, raw_result in value.items():
        if not isinstance(raw_result, dict):
            continue

        category = raw_result.get("category")

        if category not in {
            "malicious",
            "suspicious",
        }:
            continue

        engine_name = raw_result.get(
            "engine_name"
        )

        if not isinstance(engine_name, str):
            engine_name = str(engine_key)

        detections.append({
            "engine_name": engine_name,
            "category": category,
            "result": raw_result.get("result"),
            "method": raw_result.get("method"),
        })

    category_order = {
        "malicious": 0,
        "suspicious": 1,
    }

    return sorted(
        detections,
        key=lambda entry: (
            category_order[entry["category"]],
            entry["engine_name"].casefold(),
        ),
    )


def _normalize_timestamp(value):
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
    ):
        return None

    try:
        return datetime.fromtimestamp(
            value,
            tz=timezone.utc,
        ).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _normalize_community_votes(value):
    if not isinstance(value, dict):
        value = {}

    return {
        "harmless": _normalize_nonnegative_integer(
            value.get("harmless")
        ),
        "malicious": _normalize_nonnegative_integer(
            value.get("malicious")
        ),
    }


def _build_permalink(resource_type, resource_id):
    gui_resource_name = (
        VIRUSTOTAL_GUI_RESOURCE_NAMES.get(
            resource_type
        )
    )

    if gui_resource_name is None:
        return None

    return (
        "https://www.virustotal.com/gui/"
        f"{gui_resource_name}/{resource_id}"
    )


def normalize_virustotal_indicator(
    raw_data,
    indicator,
    indicator_type,
):
    if raw_data is None:
        return None

    if not isinstance(raw_data, dict):
        raise ValueError(
            "Invalid VirusTotal response: expected "
            "a dictionary."
        )

    data = raw_data.get("data")

    if not isinstance(data, dict):
        raise ValueError(
            "Invalid VirusTotal response: missing "
            "data object."
        )

    attributes = data.get("attributes")

    if not isinstance(attributes, dict):
        raise ValueError(
            "Invalid VirusTotal response: missing "
            "attributes object."
        )

    resource_id = data.get("id")
    resource_type = data.get("type")

    if (
        not isinstance(resource_id, str)
        or not resource_id.strip()
        or not isinstance(resource_type, str)
        or not resource_type.strip()
    ):
        raise ValueError(
            "Invalid VirusTotal response: missing "
            "resource identity."
        )

    stats = _normalize_analysis_stats(
        attributes
    )

    reputation = attributes.get("reputation")

    if (
        not isinstance(reputation, int)
        or isinstance(reputation, bool)
    ):
        reputation = None

    return {
        "indicator": indicator.strip(),
        "indicator_type": indicator_type,
        "resource_type": resource_type,
        "resource_id": resource_id,
        **stats,
        "reputation": reputation,
        "community_votes": (
            _normalize_community_votes(
                attributes.get("total_votes")
            )
        ),
        "detections": _normalize_detections(
            attributes.get(
                "last_analysis_results"
            )
        ),
        "categories": _normalize_categories(
            attributes.get("categories")
        ),
        "tags": _normalize_string_list(
            attributes.get("tags")
        ),
        "names": _normalize_string_list(
            attributes.get("names")
        ),
        "meaningful_name": attributes.get(
            "meaningful_name"
        ),
        "file_type": attributes.get(
            "type_description"
        ),
        "country": attributes.get("country"),
        "asn": attributes.get("asn"),
        "as_owner": attributes.get("as_owner"),
        "last_analysis_date": (
            _normalize_timestamp(
                attributes.get(
                    "last_analysis_date"
                )
            )
        ),
        "permalink": _build_permalink(
            resource_type,
            resource_id,
        ),
    }
