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

def synchronize_all_github_advisories():
    
    after =None
    batch_number=1
    per_page = 100

    modified_since=get_latest_github_advisory_updated_at()

    if modified_since is None:
           print("starting full  github advisories synchronization")

    else :
           print("starting incremental github advisory synchronization "f"from {modified_since}")

    while True:
        advisories,next_cursor = fetch_github_advisories_page(
            after=after,
            per_page=per_page,
            modified_since=modified_since
        )

        if advisories is None:
            break
        
        if not advisories:
           break

        
        for advisory in advisories:
            normalized_advisory = normalize_github_advisory(
                advisory
            )

            normalized_vulnerabilities = (
                normalize_github_advisory_vulnerabilities(
                    advisory
                )
            )

            if normalized_advisory is not None:
                
                save_github_advisory(normalized_advisory)

                save_github_advisory_vulnerabilities(normalized_vulnerabilities)

        print(f"GitHub advisory batch {batch_number} synchronized")
        if next_cursor is None:
           break
        after=next_cursor
        batch_number += 1
if __name__ == "__main__":
    synchronize_all_github_advisories()