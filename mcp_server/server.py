
import asyncio

from mcp.server.fastmcp import FastMCP
from datetime import datetime, timedelta
from database.article_repository import (
  search_articles,
  get_article_details
)

from database.cve_repository import(
  search_cves as search_cves_db,

)

from enrichment.cve_lookup_service import lookup_cve


from database.threat_search import(
  search_malware as search_malware_db,
  search_mitre as search_mitre_db,
  search_apt_groups as search_apt_groups_db,
  search_targeted_sectors as search_targeted_sectors_db,
  search_affected_technologies as search_affected_technologies_db
)
from database.github_advisory_repository import(
  search_github_advisories as search_github_advisories_db,
  get_github_advisory_details as get_github_advisory_details_db
)
from database.mitre_repository import (
    search_mitre_techniques as search_mitre_techniques_db,
    get_mitre_technique_details as get_mitre_technique_details_db,
)
from semantic_search.subprocess_service import (
  run_semantic_search_worker,
)

from database.otx_repository import ( get_otx_indicator_details,get_otx_last_checked,)
from collectors.otx_collector import enrich_otx_indicator
mcp = FastMCP("ThreatIntelMCP")

@mcp.tool()
def ping() -> str:
  """Check whether the ThreatIntelMCP server is running."""
  return "ThreatIntelMCP is running"

@mcp.tool()
def search_threat_articles(keyword:str)->list:
  """Search analyzed threat articles using an exact keyword match.

  Use this tool when the analyst provides a known title fragment,
  malware name, vulnerability identifier, or other exact term."""
  return search_articles(keyword)

@mcp.tool()
async def semantic_search_threat_articles(
    search_query: str,
    limit: int = 10,
    ) -> list:
    """
  Search threat articles by semantic meaning rather than exact keywords.

  Use this tool when an analyst describes a threat, attack scenario,
  vulnerability, or security concept in natural language. Queries may
  be written in English or French.

  Args:
    search_query: Natural-language description of the threat or topic.
    limit: Maximum number of ranked results to return, from 1 to 50.

  Returns:
    Articles ranked by cosine similarity, including their similarity
    score, title, summary, source, link, and publication date.
  """


    return await run_semantic_search_worker(
      search_query,
      limit,
    )
@mcp.tool()
def get_threat_article_details(article_id :int)->dict|None:
  """Return complete intelligence details for a specific article ID."""
  return get_article_details(article_id)
@mcp.tool()
def search_cves(keyword :str)-> list:
  """Search enriched CVEs by identifier, description, or severity."""
  return search_cves_db(keyword)

@mcp.tool()
async def get_cve_details(cve_id: str) -> dict | None:
  """
  Retrieve complete details for an exact CVE identifier.

  The local PostgreSQL cache is used when fresh. Missing or stale
  records are automatically refreshed from NVD before being returned.
  """
  return await asyncio.to_thread(
    lookup_cve,
    cve_id,
  )
@mcp.tool()
def search_malware(keyword: str)->list:
  """search articles mentioning a malware family"""
  return search_malware_db(keyword)


@mcp.tool()
def search_mitre(keyword: str)->list:
  """Search articles mentioning a MITRE ATT&CK technique ID."""
  return search_mitre_db(keyword)

@mcp.tool()
def search_apt_groups(keyword: str)->list:
  """Search articles mentioning an APT group."""
  return search_apt_groups_db(keyword)


@mcp.tool()
def search_targeted_sectors(keyword: str)->list:
  """Search articles targeting a specific industry or sector."""
  return search_targeted_sectors_db(keyword)


@mcp.tool()
def search_affected_technologies(keyword: str)->list:
  """Search articles affecting a specific product, platform, or technology."""
  return search_affected_technologies_db(keyword)

@mcp.tool()
def search_github_advisories(keyword:str)->list:
  """search github security advisory by ghsa id,cve,summary or severity """
  return search_github_advisories_db(keyword)

@mcp.tool()
def get_github_advisory_details(ghsa_id: str) -> dict | None:
    """Retrieve complete details for one GitHub Security Advisory by GHSA ID."""
    return get_github_advisory_details_db(ghsa_id)

@mcp.tool()
def search_mitre_techniques(keyword:str):
   """
    Search MITRE ATT&CK techniques by ID or name.
    Args:
        keyword: Technique ID (e.g. T1190) or technique name.
    Returns:
        Matching MITRE ATT&CK techniques.
    """
   return search_mitre_techniques_db(keyword)

@mcp.tool()
def get_mitre_technique_details(
    technique_id: str,
):
    """
    Get detailed information about a MITRE ATT&CK technique.

    Args:
        technique_id: MITRE ATT&CK technique ID
            (e.g. T1190).

    Returns:
        Detailed MITRE ATT&CK technique information.
    """
    return get_mitre_technique_details_db(
        technique_id
    )


@mcp.tool()
def lookup_otx_indicator(
    indicator: str,
    indicator_type: str,
):

    """
    Look up an IP address, domain, URL, or file hash using the local OTX cache.
    If the indicator is not present or the cached data is stale, automatically
    retrieve the latest information from AlienVault OTX, store it locally,
    and return the complete threat intelligence record.
    """
    last_checked = get_otx_last_checked(
        indicator,
        indicator_type,
    )

    if last_checked is not None:
        cache_age = datetime.now() - last_checked

        if cache_age < timedelta(hours=24):
            return get_otx_indicator_details(
                indicator,
                indicator_type,
            )

    enrich_otx_indicator(
        indicator,
        indicator_type,
    )

    return get_otx_indicator_details(
        indicator,
        indicator_type,
    )


if __name__ == "__main__":
  mcp.run(transport="stdio")
