import re
from datetime import datetime, timedelta

from database.cve_repository import (
  get_cve_details,
  get_cve_last_enriched_at,
  save_cve_enrichment,
)
from enrichment.cve_enricher import (
  fetch_cve_from_nvd,
  normalize_cve_data,
)


CVE_ID_PATTERN = re.compile(
  r"^CVE-\d{4}-\d{4,}$",
  re.IGNORECASE,
)

CVE_CACHE_MAX_AGE = timedelta(hours=24)

def normalize_cve_id(cve_id):
  if not isinstance(cve_id,str):
    raise ValueError("CVE ID must be a string.")

  normalized_cve_id=cve_id.strip().upper()

  if not CVE_ID_PATTERN.fullmatch(normalized_cve_id):
    raise ValueError("CVE ID must follow the format CVE-YYYY-NNNN ")
  return normalized_cve_id

def is_cve_cache_fresh(last_enriched_at):
  if last_enriched_at is None:
    return False

  if not isinstance(last_enriched_at, datetime):
    raise ValueError(
      "Last enrichment timestamp must be a datetime."
    )

  cache_age = datetime.now() - last_enriched_at

  return cache_age < CVE_CACHE_MAX_AGE



def refresh_cve_from_nvd(cve_id):
  normalized_cve_id = normalize_cve_id(cve_id)

  raw_cve_data = fetch_cve_from_nvd(
    normalized_cve_id
  )

  if raw_cve_data is None:
    return None

  normalized_cve = normalize_cve_data(
    raw_cve_data
  )

  if normalized_cve is None:
    return None

  returned_cve_id = normalized_cve["cve_id"].upper()

  if returned_cve_id != normalized_cve_id:
    return None

  save_cve_enrichment(normalized_cve)

  return get_cve_details(normalized_cve_id)


def lookup_cve(cve_id):
  normalized_cve_id=normalize_cve_id(cve_id)

  cached_cve=get_cve_details(normalized_cve_id)
  last_enriched_at=get_cve_last_enriched_at(normalized_cve_id)

  if (cached_cve is not None and
    is_cve_cache_fresh(last_enriched_at)
  ):
    return cached_cve

  refreshed_cve=refresh_cve_from_nvd(normalized_cve_id)
  if refreshed_cve is not None:
    return refreshed_cve

  return cached_cve