from sqlalchemy import text
import json
from database.connection import engine
import re

MAX_CVE_SEARCH_LIMIT = 50
MAX_CVE_SEARCH_KEYWORD_LENGTH = 200
MAX_CVE_SUPPORTING_ARTICLE_LIMIT = 50

CVE_ID_PATTERN = re.compile(
    r"^CVE-\d{4}-\d{4,}$",
    re.IGNORECASE,
)

def save_cve_enrichment(enriched_cve):
  with engine.connect() as connection:
    query = text("""
     INSERT INTO cve_enrichment(
      cve_id,
      description,
      cvss_score,
      severity,
      published,
      last_modified,
      reference_links
      )
    VALUES(
      :cve_id,
      :description,
      :cvss_score,
      :severity,
      :published,
      :last_modified,
      :reference_links
    )
    ON CONFLICT (cve_id) DO UPDATE SET
     description = EXCLUDED.description,
     cvss_score=EXCLUDED.cvss_score,
     severity = EXCLUDED.severity,
     published = EXCLUDED.published,
     last_modified=EXCLUDED.last_modified,
     reference_links=EXCLUDED.reference_links,
     enriched_at = CURRENT_TIMESTAMP;
  """

    )
    connection.execute(query, {
      "cve_id": enriched_cve["cve_id"],
      "description": enriched_cve["description"],
      "cvss_score": enriched_cve["cvss_score"],
      "severity": enriched_cve["severity"],
      "published": enriched_cve["published"],
      "last_modified": enriched_cve["last_modified"],
      "reference_links": json.dumps(
        enriched_cve["reference_links"]
      ),
    })


    connection.commit()



#mcp v1.0
def search_cves(
    keyword,
    limit=10,
    offset=0,
):
  if not isinstance(keyword, str):
    raise ValueError(
      "CVE search keyword must be a string."
    )

  normalized_keyword = keyword.strip()

  if not normalized_keyword:
    raise ValueError(
      "CVE search keyword cannot be empty."
    )

  if (
    len(normalized_keyword)
    > MAX_CVE_SEARCH_KEYWORD_LENGTH
  ):
    raise ValueError(
      "CVE search keyword cannot exceed "
      f"{MAX_CVE_SEARCH_KEYWORD_LENGTH} "
      "characters."
    )

  if (
    not isinstance(limit, int)
    or isinstance(limit, bool)
    or limit < 1
    or limit > MAX_CVE_SEARCH_LIMIT
  ):
    raise ValueError(
      "CVE search limit must be an integer "
      f"between 1 and {MAX_CVE_SEARCH_LIMIT}."
    )

  if (
    not isinstance(offset, int)
    or isinstance(offset, bool)
    or offset < 0
  ):
    raise ValueError(
      "CVE search offset must be a "
      "non-negative integer."
    )
  query=text(
    """
    SELECT
      cve_id,
      description,
      cvss_score,
      severity,
      published,
      last_modified
    FROM cve_enrichment
    WHERE cve_id ILIKE :keyword
      OR description ILIKE :keyword
      OR severity ILIKE :keyword
    ORDER BY
      published DESC NULLS LAST,
      cve_id ASC
    LIMIT :limit
    OFFSET :offset;

"""
  )

  with engine.connect() as connection:
    result=connection.execute(
      query,
      {
        "keyword": f"%{normalized_keyword}%",
        "limit": limit,
        "offset": offset,
      }
    )
    rows=result.fetchall()

  cves=[]
  for row in rows:
    cves.append({
      "cve_id" :row.cve_id,
      "description":row.description,
      "cvss_score":(
        float(row.cvss_score)
        if row.cvss_score is not None
        else None
      ),
      "severity" :row.severity,
      "published":(
        row.published.isoformat()
        if row.published is not None
        else None
      ),
      "last_modified":(
        row.last_modified.isoformat()
        if row.last_modified is not None
        else None
      )
    })
  return cves

def get_cve_details(cve_id):
  query=text(
    """
    SELECT
      cve_id,
      description,
      cvss_score,
      severity,
      published,
      last_modified,
      reference_links,
      enriched_at
    FROM cve_enrichment
    WHERE cve_id = :cve_id;

"""
  )

  with engine.connect() as connection :
    result = connection.execute(
      query,
      {"cve_id":cve_id}
    )
    row=result.fetchone()

    if row is None:
      return None
    return{
      "cve_id":row.cve_id,
      "description" : row.description,
      "cvss_score":(
        float(row.cvss_score)
        if row.cvss_score is not None
        else None
      ),
      "severity":row.severity,
      "published":(
        row.published.isoformat()
        if row.published is not None
        else None
      ),
      "last_modified":(
        row.last_modified.isoformat()
        if row.last_modified is not None
        else None
      ),
      "reference_links":row.reference_links,
            "enriched_at": (
        row.enriched_at.isoformat()
        if row.enriched_at is not None
        else None
      ),
    }

def get_cve_last_enriched_at(cve_id):
  query = text("""
    SELECT enriched_at
    FROM cve_enrichment
    WHERE cve_id = :cve_id;
  """)

  with engine.connect() as connection:
    result = connection.execute(
      query,
      {"cve_id": cve_id},
    )
    return result.scalar_one_or_none()

def get_cve_supporting_articles(
    cve_id,
    limit=20,
):
    if not isinstance(cve_id, str):
        raise ValueError(
            "CVE ID must be a string."
        )

    normalized_cve_id = (
        cve_id.strip().upper()
    )

    if not CVE_ID_PATTERN.fullmatch(
        normalized_cve_id
    ):
        raise ValueError(
            "CVE ID must follow the format "
            "CVE-YYYY-NNNN."
        )

    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or limit < 1
        or limit
        > MAX_CVE_SUPPORTING_ARTICLE_LIMIT
    ):
        raise ValueError(
            "Supporting article limit must be "
            "between 1 and 50."
        )

    query = text(
        """
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
        WHERE EXISTS (
            SELECT 1
            FROM jsonb_array_elements_text(
                CASE
                    WHEN jsonb_typeof(article_analysis.cves)
                      = 'array'
                    THEN article_analysis.cves
                    ELSE '[]'::jsonb
                END
            ) AS cve_value
            WHERE UPPER(cve_value) = :cve_id
        )
        ORDER BY
            articles.published DESC NULLS LAST,
            articles.id DESC
        LIMIT :limit;
        """
    )

    with engine.connect() as connection:
        rows = connection.execute(
            query,
            {
                "cve_id": normalized_cve_id,
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
                if row.confidence_score
                is not None
                else None
            ),
        }
        for row in rows
    ]

    return {
        "cve_id": normalized_cve_id,
        "supporting_article_count": (
            supporting_article_count
        ),
        "articles": articles,
    }