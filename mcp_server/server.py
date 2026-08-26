
import asyncio
import logging

from observability.logging_config import (
    configure_logging,
)
from mcp.server.fastmcp import FastMCP
from database.article_repository import (
  search_articles,
  get_article_details
)
from database.cve_repository import (
  get_cve_supporting_articles as get_cve_supporting_articles_db,
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
from database.github_advisory_repository import (
  get_github_advisory_details as get_github_advisory_details_db,
  get_github_advisory_supporting_articles as get_ghsa_supporting_articles_db,
  search_github_advisories as search_github_advisories_db,
)
from database.mitre_repository import (
  get_mitre_supporting_articles as get_mitre_supporting_articles_db,
  get_mitre_technique_details as get_mitre_technique_details_db,
  search_mitre_techniques as search_mitre_techniques_db,
)
from semantic_search.subprocess_service import (
  run_semantic_search_worker,
)

from correlation.article_investigation_service import (
    get_article_investigation as get_article_investigation_service,
)

from enrichment.otx_lookup_service import (
    lookup_otx_indicator as lookup_otx_indicator_service,
)
from enrichment.virustotal_lookup_service import (
    lookup_virustotal_indicator
    as lookup_virustotal_indicator_service,
)

from correlation.indicator_correlation_service import (
    correlate_indicator as correlate_indicator_service,
)
from scoring.article_scoring_service import (
    score_article as score_article_service,
)
from scoring.indicator_scoring_service import (
    score_indicator as score_indicator_service,
)


from pipeline.ingestion_service import (
    ingest_rss_articles as ingest_rss_articles_service,
)
from pipeline.automation_service import (
    get_pipeline_status as get_pipeline_status_service,
    index_pending_embeddings as index_pending_embeddings_service,
    process_pending_articles as process_pending_articles_service,
    synchronize_github_intelligence as synchronize_github_intelligence_service,
    synchronize_mitre_intelligence as synchronize_mitre_intelligence_service,
)
from topic_modeling.emerging_topic_service import (
    detect_emerging_topics as detect_emerging_topics_service,
)
logger = logging.getLogger(__name__)

# TODO(POST-PFE-001):
# Add per-tool audit events before exposing
# MCP through a remote multi-user transport.


mcp = FastMCP("ThreatIntelMCP")

def _get_confirmation_response(
    operation,
    confirm,
):
    if not isinstance(confirm, bool):
        raise ValueError(
            "confirm must be a boolean."
        )

    if confirm:
        return None

    return {
        "operation": operation,
        "status": "confirmation_required",
        "message": (
            "Explicit confirmation is required "
            "before this operation can run."
        ),
    }

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
def get_emerging_threat_topics(
    observation_days: int = 30,
    recent_days: int = 7,
    limit: int = 10,
) -> dict:
    """
    Detect recurring and emerging threat topics
    from recent article embeddings.

    The result includes trend direction,
    relative article shares, representative
    articles, sources, CVEs, malware, MITRE
    techniques, APT groups, sectors, and
    affected technologies.

    Args:
        observation_days:
            Complete observation window,
            from 2 to 90 days.
        recent_days:
            Recent period compared with the
            earlier observation period,
            from 1 to 30 days and smaller than
            observation_days.
        limit:
            Maximum number of topics returned,
            from 1 to 20.
    """
    return detect_emerging_topics_service(
        observation_days=observation_days,
        recent_days=recent_days,
        limit=limit,
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
def get_cve_supporting_articles(
  cve_id: str,
  limit: int = 20,
) -> dict | None:
  """
  Return locally stored articles mentioning an
  exact CVE identifier.

  This tool returns local article evidence and
  does not call NVD.
  """
  return get_cve_supporting_articles_db(
    cve_id,
    limit=limit,
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
def get_github_advisory_supporting_articles(
  ghsa_id: str,
  limit: int = 20,
) -> dict | None:
  """
  Return locally stored articles associated with
  a GitHub Security Advisory.

  Local evidence is correlated through the CVE
  associated with the advisory.
  """
  return (
    get_ghsa_supporting_articles_db(
      ghsa_id,
      limit=limit,
    )
  )
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
def get_mitre_technique_supporting_articles(
  technique_id: str,
  limit: int = 20,
) -> dict | None:
  """
  Return locally stored articles mentioning an
  exact MITRE ATT&CK technique identifier.

  This tool searches stored article analysis and
  does not contact MITRE.
  """
  return get_mitre_supporting_articles_db(
    technique_id,
    limit=limit,
  )

@mcp.tool()
def lookup_otx_indicator(
    indicator: str,
    indicator_type: str,
):
    """
    Look up an IP address, domain, URL, or file
    hash using the tested Day 2 OTX cache service.
    """
    return lookup_otx_indicator_service(
        indicator,
        indicator_type,
    )


@mcp.tool()
def lookup_virustotal_indicator(
    indicator: str,
    indicator_type: str,
) -> dict | None:
    """
    Retrieve a read-only VirusTotal report for an
    IP address, domain, URL, or file hash.

    The tool reuses a 24-hour PostgreSQL cache,
    records genuine missing reports, and can
    return stale cached intelligence if the
    external service is unavailable or limited.

    No file is uploaded and no scan is requested.
    """
    return lookup_virustotal_indicator_service(
        indicator,
        indicator_type,
    )


@mcp.tool()
def correlate_threat_indicator(
    indicator: str,
    include_otx: bool = True,
    include_virustotal: bool = True,
) -> dict:
    """
    Correlate a supported IOC with articles and
    related threat entities.

    The result includes supporting articles,
    CVEs, malware, MITRE techniques, APT groups,
    targeted sectors, affected technologies,
    and optional OTX and VirusTotal enrichment.

    Associations are based on supporting article
    evidence and do not prove attribution.
    """
    return correlate_indicator_service(
        indicator,
        include_otx=include_otx,
        include_virustotal=(
            include_virustotal
        ),
    )

@mcp.tool()
def investigate_threat_article(
    article_id: int,
    include_otx: bool = True,
) -> dict | None:
    """
    Build a consolidated threat investigation
    for an article.

    The result includes the article analysis,
    validated IOCs, optional OTX enrichment,
    compact CVE enrichment, and MITRE ATT&CK
    technique details.
    """
    return get_article_investigation_service(
        article_id,
        include_otx=include_otx,
    )

@mcp.tool()
def score_threat_article(
    article_id: int,
    include_otx: bool = True,
) -> dict | None:
    """
    Calculate explainable threat, confidence,
    and priority scores for an article.

    The result includes the scoring version,
    factor breakdowns, warnings, the selected
    representative OTX indicator, and the
    recommended SOC action.

    This is an evidence-based threat assessment,
    not a complete organizational risk score.
    """
    return score_article_service(
        article_id,
        include_otx=include_otx,
    )

@mcp.tool()
def score_threat_indicator(
    indicator: str,
    include_otx: bool = True,
    include_virustotal: bool = True,
) -> dict:
    """
    Calculate explainable threat, confidence,
    and priority scores for a supported IOC.

    The result combines supporting articles,
    related threat entities, local CVE and MITRE
    enrichment, optional OTX and VirusTotal
    evidence, warnings, and the recommended SOC
    action. External intelligence has the primary
    weight; local articles provide corroboration.

    Correlation indicates co-reporting evidence
    and does not prove attribution or causality.
    """
    return score_indicator_service(
        indicator,
        include_otx=include_otx,
        include_virustotal=(
            include_virustotal
        ),
    )
@mcp.tool()
def get_pipeline_status() -> dict:
    """
    Return a read-only operational status report
    for the Threat Intelligence pipeline.

    The result includes article processing,
    analysis and embedding coverage, pending work,
    enrichment dataset counts, consistency
    warnings, and overall health status.
    """
    return get_pipeline_status_service()

@mcp.tool()
def ingest_rss_articles(
    confirm: bool = False,
) -> dict:
    """
    Collect articles from configured RSS feeds
    and upsert them into PostgreSQL.

    This operation modifies stored article data.
    Set confirm to true to execute it. It does not
    run AI analysis or external enrichment.
    """
    confirmation = _get_confirmation_response(
        "ingest_rss_articles",
        confirm,
    )

    if confirmation is not None:
        return confirmation

    return ingest_rss_articles_service()

@mcp.tool()
def process_pending_articles(
    limit: int = 5,
    include_otx: bool = False,
    include_cve: bool = False,
    confirm: bool = False,
) -> dict:
    """
    Process the oldest pending articles using
    Claude analysis and semantic embeddings.

    The operation writes analysis, IOC and
    embedding data and marks successful articles
    as processed. OTX and CVE enrichment are
    optional. The maximum batch size is enforced
    by the automation service.

    Set confirm to true to execute it.
    """
    confirmation = _get_confirmation_response(
        "process_pending_articles",
        confirm,
    )

    if confirmation is not None:
        return confirmation

    return process_pending_articles_service(
        limit=limit,
        include_otx=include_otx,
        include_cve=include_cve,
    )

@mcp.tool()
def index_pending_embeddings(
    limit: int = 25,
    confirm: bool = False,
) -> dict:
    """
    Generate semantic embeddings for articles
    that do not currently have one.

    The operation writes embedding data and may
    use the local GPU. It does not call Claude,
    OTX, NVD, MITRE or GitHub.

    Set confirm to true to execute it.
    """
    confirmation = _get_confirmation_response(
        "index_pending_embeddings",
        confirm,
    )

    if confirmation is not None:
        return confirmation

    return index_pending_embeddings_service(
        limit=limit
    )

@mcp.tool()
def synchronize_mitre_intelligence(
    domains: list[str] | None = None,
    confirm: bool = False,
) -> dict:
    """
    Synchronize supported MITRE ATT&CK domains.

    When domains is omitted, enterprise, mobile
    and ICS ATT&CK are synchronized. The operation
    downloads official datasets and upserts
    technique records in PostgreSQL.

    Set confirm to true to execute it.
    """
    confirmation = _get_confirmation_response(
        "synchronize_mitre_intelligence",
        confirm,
    )

    if confirmation is not None:
        return confirmation

    return synchronize_mitre_intelligence_service(
        domains=domains
    )


@mcp.tool()
def synchronize_github_intelligence(
    confirm: bool = False,
) -> dict:
    """
    Incrementally synchronize reviewed GitHub
    Security Advisories and affected packages.

    The operation calls GitHub and upserts advisory
    and vulnerability records in PostgreSQL.

    Set confirm to true to execute it.
    """
    confirmation = _get_confirmation_response(
        "synchronize_github_intelligence",
        confirm,
    )

    if confirmation is not None:
        return confirmation

    return (
        synchronize_github_intelligence_service()
    )

def main():
  configure_logging()

  logger.info(
    "Starting ThreatIntelMCP MCP server "
    "with stdio transport."
  )

  try:
    mcp.run(transport="stdio")
  except Exception:
    logger.exception(
      "ThreatIntelMCP MCP server failed."
    )
    raise

  logger.info(
    "ThreatIntelMCP MCP server stopped."
  )


if __name__ == "__main__":
  main()