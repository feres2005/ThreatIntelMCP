from datetime import datetime, timedelta
import logging

import requests

from collectors.otx_collector import enrich_otx_indicator
from database.otx_repository import (
    get_otx_indicator_details,
    get_otx_last_checked,
)

logger = logging.getLogger(__name__)
OTX_CACHE_MAX_AGE = timedelta(hours=24)


def is_otx_cache_fresh(last_checked):
    if last_checked is None:
        return False

    if not isinstance(last_checked, datetime):
        raise ValueError(
            "Last OTX check timestamp must be a datetime."
        )

    cache_age = datetime.now() - last_checked

    return cache_age < OTX_CACHE_MAX_AGE

def lookup_otx_indicator(
    indicator,
    indicator_type,
):
    cached_indicator = get_otx_indicator_details(
        indicator,
        indicator_type,
    )

    last_checked = get_otx_last_checked(
        indicator,
        indicator_type,
    )

    if (
        cached_indicator is not None
        and is_otx_cache_fresh(last_checked)
    ):
        return cached_indicator

    try:
        enrich_otx_indicator(
            indicator,
            indicator_type,
        )

    except (
        requests.RequestException,
        ValueError,
    ) as error:
        logger.warning(
            "OTX refresh failed for %s (%s): %s",
            indicator,
            indicator_type,
            error,
        )

        return cached_indicator

    refreshed_indicator = get_otx_indicator_details(
        indicator,
        indicator_type,
    )

    return refreshed_indicator


def lookup_otx_indicators(iocs):
    results = []

    for ioc in iocs:
        result = lookup_otx_indicator(
            ioc["indicator"],
            ioc["indicator_type"],
        )
        results.append(result)

    return results