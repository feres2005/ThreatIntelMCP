from datetime import datetime, timedelta, timezone
import logging

import requests

from collectors.virustotal_collector import (
    fetch_virustotal_indicator,
    get_virustotal_resource_path,
    normalize_virustotal_indicator,
)
from database.virustotal_repository import (
    get_virustotal_indicator_details,
    get_virustotal_last_checked,
    save_virustotal_indicator,
)


logger = logging.getLogger(__name__)

VIRUSTOTAL_CACHE_MAX_AGE = timedelta(
    hours=24
)


def is_virustotal_cache_fresh(
    last_checked,
):
    if last_checked is None:
        return False

    if not isinstance(last_checked, datetime):
        raise ValueError(
            "Last VirusTotal check timestamp "
            "must be a datetime."
        )

    if last_checked.tzinfo is None:
        last_checked = last_checked.replace(
            tzinfo=timezone.utc
        )
    else:
        last_checked = last_checked.astimezone(
            timezone.utc
        )

    cache_age = (
        datetime.now(timezone.utc)
        - last_checked
    )

    return cache_age < VIRUSTOTAL_CACHE_MAX_AGE


def _with_lookup_metadata(
    result,
    cache_status,
):
    if result is None:
        return None

    return {
        **result,
        "source": "virustotal",
        "cache_status": cache_status,
        "is_stale": (
            cache_status == "stale_fallback"
        ),
    }


def lookup_virustotal_indicator(
    indicator,
    indicator_type,
):
    get_virustotal_resource_path(
        indicator,
        indicator_type,
    )

    normalized_indicator = indicator.strip()

    cached_indicator = (
        get_virustotal_indicator_details(
            normalized_indicator,
            indicator_type,
        )
    )
    last_checked = get_virustotal_last_checked(
        normalized_indicator,
        indicator_type,
    )

    if (
        cached_indicator is not None
        and is_virustotal_cache_fresh(
            last_checked
        )
    ):
        return _with_lookup_metadata(
            cached_indicator,
            "fresh",
        )

    try:
        raw_data = fetch_virustotal_indicator(
            normalized_indicator,
            indicator_type,
        )
        normalized_result = (
            normalize_virustotal_indicator(
                raw_data,
                normalized_indicator,
                indicator_type,
            )
        )
    except (
        requests.RequestException,
        ValueError,
    ) as error:
        logger.warning(
            "VirusTotal refresh failed for %s "
            "(%s): %s",
            normalized_indicator,
            indicator_type,
            error,
        )

        return _with_lookup_metadata(
            cached_indicator,
            "stale_fallback",
        )

    if normalized_result is None:
        normalized_result = {
            "indicator": normalized_indicator,
            "indicator_type": indicator_type,
            "report_available": False,
        }
    else:
        normalized_result = {
            **normalized_result,
            "report_available": True,
        }

    save_virustotal_indicator(
        normalized_result
    )

    refreshed_indicator = (
        get_virustotal_indicator_details(
            normalized_indicator,
            indicator_type,
        )
    )

    return _with_lookup_metadata(
        (
            refreshed_indicator
            if refreshed_indicator is not None
            else normalized_result
        ),
        "refreshed",
    )