from sqlalchemy import text
import json
from database.connection import engine
MAX_GITHUB_ADVISORY_SEARCH_LIMIT = 50
MAX_GITHUB_ADVISORY_KEYWORD_LENGTH = 200
import json
import re

from sqlalchemy import text


from database.connection import engine


MAX_GITHUB_ADVISORY_SEARCH_LIMIT = 50
MAX_GITHUB_ADVISORY_KEYWORD_LENGTH = 200

GITHUB_ADVISORY_ID_PATTERN = re.compile(
    (
        r"^GHSA-[a-z0-9]{4}-"
        r"[a-z0-9]{4}-[a-z0-9]{4}$"
    ),
    re.IGNORECASE,
)

SUPPORTED_GITHUB_ADVISORY_SEVERITIES = {
    "low",
    "medium",
    "high",
    "critical",
}

SUPPORTED_GITHUB_ADVISORY_ECOSYSTEMS = {
    "actions",
    "composer",
    "erlang",
    "go",
    "maven",
    "npm",
    "nuget",
    "pip",
    "pub",
    "rubygems",
    "rust",
    "swift",
}

SUPPORTED_GITHUB_ADVISORY_SEVERITIES = {
    "low",
    "medium",
    "high",
    "critical",
}
GITHUB_ADVISORY_ID_PATTERN = re.compile(
    (
        r"^GHSA-[a-z0-9]{4}-"
        r"[a-z0-9]{4}-[a-z0-9]{4}$"
    ),
    re.IGNORECASE,
)

def save_github_advisory(advisory):
  with engine.connect() as connection:

    query=text(
    """
    INSERT INTO github_advisories(

      ghsa_id,
      cve_id,
      type,
      summary,
      description,
      severity,
      published_at,
      updated_at,
      github_reviewed_at,
      nvd_published_at,
      withdrawn_at,
      cvss_v3_score,
      cvss_v3_vector,
      cvss_v4_score,
      cvss_v4_vector,
      cwe_ids,
      reference_links
    
    )
    VALUES(
      :ghsa_id,
      :cve_id,
      :type,
      :summary,
      :description,
      :severity,
      :published_at,
      :updated_at,
      :github_reviewed_at,
      :nvd_published_at,
      :withdrawn_at,
      :cvss_v3_score,
      :cvss_v3_vector,
      :cvss_v4_score,
      :cvss_v4_vector,
      :cwe_ids,
      :reference_links
    
    )
    ON CONFLICT(ghsa_id)
    DO UPDATE SET
      cve_id=EXCLUDED.cve_id,
      type=EXCLUDED.type,
      summary=EXCLUDED.summary,
      description=EXCLUDED.description,
      severity=EXCLUDED.severity,
      published_at=EXCLUDED.published_at,
      updated_at=EXCLUDED.updated_at,
      github_reviewed_at=EXCLUDED.github_reviewed_at,
      nvd_published_at=EXCLUDED.nvd_published_at,
      withdrawn_at=EXCLUDED.withdrawn_at,
      cvss_v3_score=EXCLUDED.cvss_v3_score,
      cvss_v3_vector=EXCLUDED.cvss_v3_vector,
      cvss_v4_score=EXCLUDED.cvss_v4_score,
      cvss_v4_vector=EXCLUDED.cvss_v4_vector,
      cwe_ids=EXCLUDED.cwe_ids,
      reference_links=EXCLUDED.reference_links
"""
    
      )
    connection.execute(
      query,
      {
        "ghsa_id":advisory["ghsa_id"],
        "cve_id":advisory["cve_id"],
        "type":advisory["type"],
        "summary":advisory["summary"],
        "description":advisory["description"],
        "severity":advisory["severity"],
        "published_at":advisory["published_at"],
        "updated_at":advisory["updated_at"],
        "github_reviewed_at":advisory["github_reviewed_at"],
        "nvd_published_at":advisory["nvd_published_at"],
        "withdrawn_at":advisory["withdrawn_at"],
        "cvss_v3_score":advisory["cvss_v3_score"],
        "cvss_v3_vector":advisory["cvss_v3_vector"],
        "cvss_v4_score":advisory["cvss_v4_score"],
        "cvss_v4_vector":advisory["cvss_v4_vector"],
        "cwe_ids":advisory["cwe_ids"],
        "reference_links":json.dumps(advisory["reference_links"])

      }

    )

    connection.commit()


def search_github_advisories(
    keyword,
    limit=10,
    offset=0,
    severity=None,
    ecosystem=None,
):
  if not isinstance(keyword, str):
    raise ValueError(
      "GitHub advisory search keyword "
      "must be a string."
    )

  normalized_keyword = keyword.strip()

  if not normalized_keyword:
    raise ValueError(
      "GitHub advisory search keyword "
      "cannot be empty."
    )

  if (
    len(normalized_keyword)
    > MAX_GITHUB_ADVISORY_KEYWORD_LENGTH
  ):
    raise ValueError(
      "GitHub advisory search keyword "
      "cannot exceed "
      f"{MAX_GITHUB_ADVISORY_KEYWORD_LENGTH} "
      "characters."
    )

  if (
    not isinstance(limit, int)
    or isinstance(limit, bool)
    or limit < 1
    or limit > MAX_GITHUB_ADVISORY_SEARCH_LIMIT
  ):
    raise ValueError(
      "GitHub advisory search limit must "
      "be an integer between 1 and "
      f"{MAX_GITHUB_ADVISORY_SEARCH_LIMIT}."
    )

  if (
    not isinstance(offset, int)
    or isinstance(offset, bool)
    or offset < 0
  ):
    raise ValueError(
      "GitHub advisory search offset must "
      "be a non-negative integer."
    )

  normalized_ecosystem = None

  if ecosystem is not None:
    if not isinstance(ecosystem, str):
      raise ValueError(
        "GitHub advisory ecosystem must "
        "be a string or None."
      )

    normalized_ecosystem = (
      ecosystem.strip().lower()
    )

    if (
      normalized_ecosystem
      not in
      SUPPORTED_GITHUB_ADVISORY_ECOSYSTEMS
    ):
      raise ValueError(
        "Unsupported GitHub advisory "
        f"ecosystem: {ecosystem!r}."
      )

  normalized_severity = None

  if severity is not None:
    if not isinstance(severity, str):
      raise ValueError(
        "GitHub advisory severity must "
        "be a string or None."
      )

    normalized_severity = (
      severity.strip().lower()
    )

    if (
      normalized_severity
      not in
      SUPPORTED_GITHUB_ADVISORY_SEVERITIES
    ):
      raise ValueError(
        "Unsupported GitHub advisory "
        f"severity: {severity!r}."
      )

  query = text(
    """
    SELECT
      ghsa_id,
      cve_id,
      summary,
      severity,
      published_at,
      updated_at,
      cvss_v3_score,
      cvss_v4_score
    FROM github_advisories
    WHERE (
      github_advisories.ghsa_id
        ILIKE :keyword
      OR github_advisories.cve_id
        ILIKE :keyword
      OR github_advisories.summary
        ILIKE :keyword
      OR github_advisories.description
        ILIKE :keyword
      OR github_advisories.severity
        ILIKE :keyword
      OR EXISTS (
        SELECT 1
        FROM github_advisory_vulnerabilities
          AS keyword_vulnerability
        WHERE
          keyword_vulnerability.ghsa_id
            = github_advisories.ghsa_id
          AND (
            keyword_vulnerability.package_name
              ILIKE :keyword
            OR keyword_vulnerability.ecosystem
              ILIKE :keyword
          )
      )
    )
    AND (
      :severity IS NULL
      OR github_advisories.severity
        = :severity
    )
    AND (
      :ecosystem IS NULL
      OR EXISTS (
        SELECT 1
        FROM github_advisory_vulnerabilities
          AS ecosystem_vulnerability
        WHERE
          ecosystem_vulnerability.ghsa_id
            = github_advisories.ghsa_id
          AND ecosystem_vulnerability.ecosystem
            = :ecosystem
      )
    )
    ORDER BY
      published_at DESC NULLS LAST,
      ghsa_id ASC
    LIMIT :limit
    OFFSET :offset;
    """
  )

  parameters = {
    "keyword": f"%{normalized_keyword}%",
    "limit": limit,
    "offset": offset,
    "severity": normalized_severity,
    "ecosystem": normalized_ecosystem,
  }
  with engine.connect() as connection:
    result = connection.execute(
      query,
      parameters,
    )

    rows = result.fetchall()

  advisories = []

  for row in rows:
    advisories.append({
      "ghsa_id": row.ghsa_id,
      "cve_id": row.cve_id,
      "summary": row.summary,
      "severity": row.severity,
      "published_at": (
        row.published_at.isoformat()
        if row.published_at is not None
        else None
      ),
      "updated_at": (
        row.updated_at.isoformat()
        if row.updated_at is not None
        else None
      ),
      "cvss_v3_score": (
        float(row.cvss_v3_score)
        if row.cvss_v3_score is not None
        else None
      ),
      "cvss_v4_score": (
        float(row.cvss_v4_score)
        if row.cvss_v4_score is not None
        else None
      ),
    })

  return advisories
def get_github_advisory_details(ghsa_id):
    advisory_query = text("""
        SELECT
            ghsa_id,
            cve_id,
            type,
            summary,
            description,
            severity,
            published_at,
            updated_at,
            github_reviewed_at,
            nvd_published_at,
            withdrawn_at,
            cvss_v3_score,
            cvss_v3_vector,
            cvss_v4_score,
            cvss_v4_vector,
            cwe_ids,
            reference_links
        FROM github_advisories
        WHERE ghsa_id = :ghsa_id;
    """)

    vulnerabilities_query = text("""
        SELECT
            ecosystem,
            package_name,
            vulnerable_version_range,
            first_patched_version,
            vulnerable_functions
        FROM github_advisory_vulnerabilities
        WHERE ghsa_id = :ghsa_id
        ORDER BY package_name;
    """)

    with engine.connect() as connection:
        advisory_row = connection.execute(
            advisory_query,
            {"ghsa_id": ghsa_id}
        ).fetchone()

        if advisory_row is None:
            return None

        vulnerability_rows = connection.execute(
            vulnerabilities_query,
            {"ghsa_id": ghsa_id}
        ).fetchall()

    advisory = {
        "ghsa_id": advisory_row.ghsa_id,
        "cve_id": advisory_row.cve_id,
        "type": advisory_row.type,
        "summary": advisory_row.summary,
        "description": advisory_row.description,
        "severity": advisory_row.severity,
        "published_at": (
            advisory_row.published_at.isoformat()
            if advisory_row.published_at
            else None
        ),
        "updated_at": (
            advisory_row.updated_at.isoformat()
            if advisory_row.updated_at
            else None
        ),
        "github_reviewed_at": (
            advisory_row.github_reviewed_at.isoformat()
            if advisory_row.github_reviewed_at
            else None
        ),
        "nvd_published_at": (
            advisory_row.nvd_published_at.isoformat()
            if advisory_row.nvd_published_at
            else None
        ),
        "withdrawn_at": (
            advisory_row.withdrawn_at.isoformat()
            if advisory_row.withdrawn_at
            else None
        ),
        "cvss_v3_score": (
            float(advisory_row.cvss_v3_score)
            if advisory_row.cvss_v3_score is not None
            else None
        ),
        "cvss_v3_vector": advisory_row.cvss_v3_vector,
        "cvss_v4_score": (
            float(advisory_row.cvss_v4_score)
            if advisory_row.cvss_v4_score is not None
            else None
        ),
        "cvss_v4_vector": advisory_row.cvss_v4_vector,
        "cwe_ids": advisory_row.cwe_ids,
        "reference_links": advisory_row.reference_links,
        "vulnerabilities": []
    }

    for row in vulnerability_rows:
        advisory["vulnerabilities"].append({
            "ecosystem": row.ecosystem,
            "package_name": row.package_name,
            "vulnerable_version_range": row.vulnerable_version_range,
            "first_patched_version": row.first_patched_version,
            "vulnerable_functions": row.vulnerable_functions
        })

    return advisory

def get_github_advisory_supporting_articles(
    ghsa_id,
    limit=20,
):
  if not isinstance(ghsa_id, str):
    raise ValueError(
      "GitHub advisory ID must be a string."
    )

  cleaned_ghsa_id = ghsa_id.strip()

  if (
    GITHUB_ADVISORY_ID_PATTERN.fullmatch(
      cleaned_ghsa_id
    )
    is None
  ):
    raise ValueError(
      "GitHub advisory ID is invalid."
    )

  normalized_ghsa_id = (
    "GHSA-"
    + cleaned_ghsa_id[5:].lower()
  )

  if (
    not isinstance(limit, int)
    or isinstance(limit, bool)
    or limit < 1
    or limit > 50
  ):
    raise ValueError(
      "Supporting article limit must be "
      "between 1 and 50."
    )

  advisory_query = text("""
    SELECT cve_id
    FROM github_advisories
    WHERE ghsa_id = :ghsa_id;
  """)

  articles_query = text("""
    SELECT
      articles.id AS article_id,
      articles.title,
      articles.link,
      articles.source,
      articles.published,
      article_analysis.severity,
      article_analysis.confidence_score,
      COUNT(*) OVER()
        AS supporting_article_count
    FROM articles
    JOIN article_analysis
      ON article_analysis.article_id
        = articles.id
    WHERE
      jsonb_typeof(
        article_analysis.cves
      ) = 'array'
      AND EXISTS (
        SELECT 1
        FROM jsonb_array_elements_text(
          article_analysis.cves
        ) AS cve_value
        WHERE UPPER(cve_value)
          = :cve_id
      )
    ORDER BY
      articles.published DESC NULLS LAST,
      articles.id DESC
    LIMIT :limit;
  """)

  with engine.connect() as connection:
    advisory_row = connection.execute(
      advisory_query,
      {"ghsa_id": normalized_ghsa_id},
    ).fetchone()

    if advisory_row is None:
      return None

    if advisory_row.cve_id is None:
      rows = []
    else:
      rows = connection.execute(
        articles_query,
        {
          "cve_id": (
            advisory_row.cve_id.upper()
          ),
          "limit": limit,
        },
      ).fetchall()

  supporting_article_count = (
    int(rows[0].supporting_article_count)
    if rows
    else 0
  )

  articles = [
    {
      "article_id": row.article_id,
      "title": row.title,
      "link": row.link,
      "source": row.source,
      "published": (
        row.published.isoformat()
        if row.published is not None
        else None
      ),
      "severity": row.severity,
      "confidence_score": (
        float(row.confidence_score)
        if row.confidence_score is not None
        else None
      ),
    }
    for row in rows
  ]

  return {
    "ghsa_id": normalized_ghsa_id,
    "cve_id": advisory_row.cve_id,
    "limit": limit,
    "supporting_article_count": (
      supporting_article_count
    ),
    "returned_count": len(articles),
    "articles": articles,
  }

def save_github_advisory_vulnerabilities(vulnerabilities):
    if not vulnerabilities:
        return

    with engine.connect() as connection:
        delete_query = text("""
            DELETE FROM github_advisory_vulnerabilities
            WHERE ghsa_id = :ghsa_id
        """)

        connection.execute(
            delete_query,
            {
                "ghsa_id": vulnerabilities[0]["ghsa_id"]
            }
        )

        query = text("""
            INSERT INTO github_advisory_vulnerabilities(
                ghsa_id,
                ecosystem,
                package_name,
                vulnerable_version_range,
                first_patched_version,
                vulnerable_functions
            )
            VALUES(
                :ghsa_id,
                :ecosystem,
                :package_name,
                :vulnerable_version_range,
                :first_patched_version,
                :vulnerable_functions
            )
        """)

        for vulnerability in vulnerabilities:
            connection.execute(
                query,
                {
                    "ghsa_id": vulnerability["ghsa_id"],
                    "ecosystem": vulnerability["ecosystem"],
                    "package_name": vulnerability["package_name"],
                    "vulnerable_version_range":
                        vulnerability["vulnerable_version_range"],
                    "first_patched_version":
                        vulnerability["first_patched_version"],
                    "vulnerable_functions":
                        vulnerability["vulnerable_functions"]
                }
            )

        connection.commit()

def get_latest_github_advisory_updated_at():
  query=text(
    """
    SELECT MAX(updated_at)
    FROM github_advisories;
""")    
  with engine.connect() as connection:
    result=connection.execute(query)
    return result.scalar()
