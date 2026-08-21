import logging
import requests
from urllib.parse import urlparse, parse_qs
import os
from dotenv import load_dotenv

from database.github_advisory_repository import (
    save_github_advisory,
    save_github_advisory_vulnerabilities,
    get_latest_github_advisory_updated_at
)
load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_ADVISORIES_API_URL="https://api.github.com/advisories"
logger=logging.getLogger(__name__)

def fetch_github_advisories_page(after=None,per_page=100,modified_since=None):
  params={
    "type":"reviewed",
    "per_page":per_page
  }
  if after:
     params["after"]=after

  if modified_since:
     params["modified"]=f">={modified_since.isoformat()}"
  headers={}
  if GITHUB_TOKEN:
     headers ["Authorization"]=f"Bearer {GITHUB_TOKEN}"

  try:
    response =requests.get(
      GITHUB_ADVISORIES_API_URL,
      params=params,
      headers=headers,
      timeout=30
    )
    response.raise_for_status()

  except requests.exceptions.HTTPError as error:
     if response.status_code==403:
        rate_limit = response.headers.get("X-RateLimit-Limit")
        remaining=response.headers.get("x-rateLimit-remaining")
        reset_time=response.headers.get("x-rateLimit-reset")
        logger.warning(
          "GitHub API rate limit reached for cursor %s. "
          "Limit: %s, remaining requests: %s, reset timestamp: %s",
          after,
          rate_limit,
          remaining,
          reset_time
)
        return None, None
     logger.error("GITHUB HTTP error for cursor %s:%s ",after,error)
     return None, None
  except requests.exceptions.RequestException as error:
     logger.error(
        "failed to fetch github advisories batch %s:%s ",
        after,
        error
     )
     return None, None

  try:
    advisories = response.json()
  except requests.exceptions.JSONDecodeError as error:
    logger.error(
      "GitHub returned invalid JSON for cursor %s: %s",
      after,
      error
    )
    return None, None
  
  next_url = response.links.get("next", {}).get("url")
  next_cursor = None
  
  if next_url:
    parsed_url = urlparse(next_url)
    query_parameters = parse_qs(parsed_url.query)
    next_cursor = query_parameters.get("after", [None])[0]
  
  return advisories, next_cursor
  

def normalize_github_advisory(raw_advisory):
  if not isinstance(raw_advisory,dict):
    logger.warning("Invalid GitHub advisory: expected a dictionary")
    return None
  ghsa_id= raw_advisory.get("ghsa_id")

  if not isinstance(ghsa_id,str) or not ghsa_id:
    logger.warning("invalid github advisory:missing or invalid ghsa id ")
    return None
  
  cvss_severities=raw_advisory.get("cvss_severities",{})
  if not isinstance(cvss_severities,dict):
    cvss_severities={}
  cvss_v3 = cvss_severities.get("cvss_v3", {})

  if not isinstance(cvss_v3, dict):
    cvss_v3 = {}

  cvss_v3_score = cvss_v3.get("score")
  cvss_v3_vector = cvss_v3.get("vector_string")

  if cvss_v3_score == 0.0 and cvss_v3_vector is None:
    cvss_v3_score = None
  cvss_v4 = cvss_severities.get("cvss_v4",{})

  if not isinstance(cvss_v4,dict):
    cvss_v4={}

  raw_cwes=raw_advisory.get("cwes",[])
  if not isinstance(raw_cwes,list):
    raw_cwes=[]
  cwe_ids=[]

  for cwe in raw_cwes:
    if not isinstance(cwe,dict):
      continue
    cwe_id =cwe.get("cwe_id")

    if isinstance(cwe_id,str) and cwe_id:
      cwe_ids.append(cwe_id)

  return {
    "ghsa_id":ghsa_id,
    "cve_id":raw_advisory.get("cve_id"),
    "type":raw_advisory.get("type"),
    "summary":raw_advisory.get("summary"),
    "description":raw_advisory.get("description"),
    "severity":raw_advisory.get("severity"),
    "published_at":raw_advisory.get("published_at"),
    "updated_at":raw_advisory.get("updated_at"),
    "github_reviewed_at":raw_advisory.get("github_reviewed_at"),
    "nvd_published_at":raw_advisory.get("nvd_published_at"),
    "withdrawn_at":raw_advisory.get("withdrawn_at"),
    "cvss_v3_score": cvss_v3_score,
    "cvss_v3_vector": cvss_v3_vector,
    "cvss_v4_score": cvss_v4.get("score"),
    "cvss_v4_vector": cvss_v4.get("vector_string"),
    "cwe_ids":cwe_ids,
    "reference_links": raw_advisory.get("references", [])
  }


def normalize_github_advisory_vulnerabilities(advisory):
  if not isinstance(advisory,dict):
    return []
  ghsa_id=advisory.get("ghsa_id")

  if not ghsa_id:
    return[]
  
  vulnerabilities=advisory.get("vulnerabilities") or []
  if not isinstance(vulnerabilities,list):
     logger.warning("Invalid vulnerabilities field for advisory %s: expected a list",ghsa_id)
     return []


  normalized_vulnerablities=[]

  for vulnerability in vulnerabilities:
    if not isinstance(vulnerability,dict):
       logger.warning("invalid vulnerability entry for advisory %s : expected a dictionary",ghsa_id)
       continue
    
    package=vulnerability.get("package") or {}
    if not isinstance(package,dict):
       package={}
    normalized_vulnerablities.append(
      {
        "ghsa_id":ghsa_id,
        "ecosystem":package.get("ecosystem"),
        "package_name":package.get("name"),
        "vulnerable_version_range":vulnerability.get("vulnerable_version_range"),
        "first_patched_version":vulnerability.get("first_patched_version"),
        "vulnerable_functions":vulnerability.get("vulnerable_functions") or []
      }
    )
  return normalized_vulnerablities

def synchronize_all_github_advisories(
    progress_callback=None,
):
    if (
        progress_callback is not None
        and not callable(progress_callback)
    ):
        raise ValueError(
            "Progress callback must be "
            "callable or None."
        )

    after = None
    batch_number = 1
    per_page = 100

    modified_since = (
        get_latest_github_advisory_updated_at()
    )

    if modified_since is None:
        synchronization_mode = "full"
        modified_since_value = None
    else:
        synchronization_mode = "incremental"
        modified_since_value = (
            modified_since.isoformat()
        )

    batch_count = 0
    fetched_advisory_count = 0
    saved_advisory_count = 0
    saved_vulnerability_count = 0
    skipped_advisory_count = 0
    failures = []
    fetch_failed = False

    while True:
        advisories, next_cursor = (
            fetch_github_advisories_page(
                after=after,
                per_page=per_page,
                modified_since=modified_since,
            )
        )

        if advisories is None:
            fetch_failed = True
            failures.append({
                "stage": "fetch",
                "batch_number": batch_number,
                "cursor": after,
                "error": (
                    "GitHub advisory page fetch "
                    "failed. Review application "
                    "logs for details."
                ),
            })
            break

        if not advisories:
            break

        batch_count += 1
        fetched_advisory_count += len(
            advisories
        )

        batch_saved_count = 0

        for position, advisory in enumerate(
            advisories,
            start=1,
        ):
            if isinstance(advisory, dict):
                ghsa_id = advisory.get("ghsa_id")
            else:
                ghsa_id = None

            try:
                normalized_advisory = (
                    normalize_github_advisory(
                        advisory
                    )
                )

                normalized_vulnerabilities = (
                    normalize_github_advisory_vulnerabilities(
                        advisory
                    )
                )
            except Exception as error:
                skipped_advisory_count += 1
                failures.append({
                    "stage": "normalization",
                    "batch_number": batch_number,
                    "position": position,
                    "ghsa_id": ghsa_id,
                    "error": (
                        f"{type(error).__name__}: "
                        f"{error}"
                    ),
                })
                continue

            if normalized_advisory is None:
                skipped_advisory_count += 1
                failures.append({
                    "stage": "normalization",
                    "batch_number": batch_number,
                    "position": position,
                    "ghsa_id": ghsa_id,
                    "error": (
                        "Advisory normalization "
                        "returned no result."
                    ),
                })
                continue

            try:
                save_github_advisory(
                    normalized_advisory
                )
            except Exception as error:
                failures.append({
                    "stage": "advisory_save",
                    "batch_number": batch_number,
                    "position": position,
                    "ghsa_id": ghsa_id,
                    "error": (
                        f"{type(error).__name__}: "
                        f"{error}"
                    ),
                })
                continue

            saved_advisory_count += 1
            batch_saved_count += 1

            try:
                save_github_advisory_vulnerabilities(
                    normalized_vulnerabilities
                )
            except Exception as error:
                failures.append({
                    "stage": "vulnerability_save",
                    "batch_number": batch_number,
                    "position": position,
                    "ghsa_id": ghsa_id,
                    "error": (
                        f"{type(error).__name__}: "
                        f"{error}"
                    ),
                })
                continue

            saved_vulnerability_count += len(
                normalized_vulnerabilities
            )

        if progress_callback is not None:
            progress_callback({
                "event": "batch_synchronized",
                "batch_number": batch_number,
                "advisory_count": len(advisories),
                "saved_advisory_count": (
                    batch_saved_count
                ),
            })

        if next_cursor is None:
            break

        after = next_cursor
        batch_number += 1

    if fetch_failed:
        status = "failed"
    elif failures:
        status = "completed_with_warnings"
    else:
        status = "completed"

    return {
        "operation": (
            "synchronize_github_advisories"
        ),
        "status": status,
        "synchronization_mode": (
            synchronization_mode
        ),
        "modified_since": modified_since_value,
        "batch_count": batch_count,
        "fetched_advisory_count": (
            fetched_advisory_count
        ),
        "saved_advisory_count": (
            saved_advisory_count
        ),
        "saved_vulnerability_count": (
            saved_vulnerability_count
        ),
        "skipped_advisory_count": (
            skipped_advisory_count
        ),
        "failure_count": len(failures),
        "failures": failures,
    }

if __name__ == "__main__":
    synchronize_all_github_advisories()