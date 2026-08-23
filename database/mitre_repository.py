from sqlalchemy import text
from database.connection import engine
import json
import re
MAX_MITRE_SEARCH_LIMIT = 50
MAX_MITRE_SEARCH_KEYWORD_LENGTH = 200

SUPPORTED_MITRE_DOMAINS = {
    "enterprise-attack",
    "mobile-attack",
    "ics-attack",
}
MAX_MITRE_SUPPORTING_ARTICLE_LIMIT = 50

MITRE_TECHNIQUE_ID_PATTERN = re.compile(
    r"^T\d{4}(?:\.\d{3})?$",
    re.IGNORECASE,
)

def save_mitre_technique(technique):
  query=text(
  """
  INSERT INTO mitre_techniques(
  stix_id,
  technique_id,
  domain,
  name,
  description,
  is_subtechnique,
  platforms,
  kill_chain_phases,
  version,
  reference_links,
  created,
  modified,
  revoked,
  deprecated
  
  )
  VALUES(
  :stix_id,
  :technique_id,
  :domain,
  :name,
  :description,
  :is_subtechnique,
  :platforms,
  :kill_chain_phases,
  :version,
  :reference_links,
  :created,
  :modified,
  :revoked,
  :deprecated
  )
  ON CONFLICT (stix_id)
  DO UPDATE SET 
    technique_id=EXCLUDED.technique_id,
    domain=EXCLUDED.domain,
    name=EXCLUDED.name,
    description=EXCLUDED.description,
    is_subtechnique=EXCLUDED.is_subtechnique,
    platforms=EXCLUDED.platforms,
    kill_chain_phases=EXCLUDED.kill_chain_phases,
    version=EXCLUDED.version,
    reference_links=EXCLUDED.reference_links,
    created=EXCLUDED.created,
    modified=EXCLUDED.modified,
    revoked=EXCLUDED.revoked,
    deprecated=EXCLUDED.deprecated

""")
  parameters=technique.copy()
  parameters["platforms"]=json.dumps(parameters["platforms"])
  parameters["kill_chain_phases"]=json.dumps(parameters["kill_chain_phases"])
  parameters["reference_links"]=json.dumps(parameters["reference_links"])
  with engine.begin() as connection:
    connection.execute(query,parameters)


def search_mitre_techniques(
    keyword,
    limit=10,
    offset=0,
    domain=None,
    include_inactive=False,
):
  if not isinstance(keyword, str):
    raise ValueError(
      "MITRE search keyword must be a string."
    )

  normalized_keyword = keyword.strip()

  if not normalized_keyword:
    raise ValueError(
      "MITRE search keyword cannot be empty."
    )

  if (
    len(normalized_keyword)
    > MAX_MITRE_SEARCH_KEYWORD_LENGTH
  ):
    raise ValueError(
      "MITRE search keyword cannot exceed "
      f"{MAX_MITRE_SEARCH_KEYWORD_LENGTH} "
      "characters."
    )

  if (
    not isinstance(limit, int)
    or isinstance(limit, bool)
    or limit < 1
    or limit > MAX_MITRE_SEARCH_LIMIT
  ):
    raise ValueError(
      "MITRE search limit must be an integer "
      f"between 1 and {MAX_MITRE_SEARCH_LIMIT}."
    )

  if (
    not isinstance(offset, int)
    or isinstance(offset, bool)
    or offset < 0
  ):
    raise ValueError(
      "MITRE search offset must be a "
      "non-negative integer."
    )

  if (
    domain is not None
    and domain not in SUPPORTED_MITRE_DOMAINS
  ):
    raise ValueError(
      f"Unsupported MITRE domain: {domain!r}."
    )

  if not isinstance(include_inactive, bool):
    raise ValueError(
      "include_inactive must be a boolean."
    )

  query = text(
  """
  SELECT
    technique_id,
    name,
    domain,
    is_subtechnique,
    version,
    revoked,
    deprecated
  FROM mitre_techniques
  WHERE (
    technique_id ILIKE :keyword
    OR name ILIKE :keyword
    OR description ILIKE :keyword
    OR EXISTS (
      SELECT 1
      FROM jsonb_array_elements_text(
        CASE
          WHEN jsonb_typeof(platforms) = 'array'
            THEN platforms
          ELSE '[]'::jsonb
        END
      ) AS platform_name
      WHERE platform_name ILIKE :keyword
    )
  )
  AND (
    :domain IS NULL
    OR domain = :domain
  )
  AND (
    :include_inactive IS TRUE
    OR (
      revoked IS FALSE
      AND deprecated IS FALSE
    )
  )
  ORDER BY
    technique_id ASC,
    domain ASC
  LIMIT :limit
  OFFSET :offset
  """
  )

  parameters = {
    "keyword": f"%{normalized_keyword}%",
    "limit": limit,
    "offset": offset,
    "domain": domain,
    "include_inactive": include_inactive,
  }

  with engine.connect() as connection:
    result = connection.execute(
      query,
      parameters,
    )

    return [
      dict(row._mapping)
      for row in result
    ]

def get_mitre_technique_details(technique_id):
    query = text("""
        SELECT
            technique_id,
            stix_id,
            name,
            description,
            domain,
            is_subtechnique,
            platforms,
            kill_chain_phases,
            version,
            reference_links,
            created,
            modified,
            revoked,
            deprecated
        FROM mitre_techniques
        WHERE technique_id = :technique_id
        LIMIT 1
    """)
    parameters={"technique_id":technique_id}
    with engine.connect() as connection:
       result=connection.execute(query,parameters)
       row=result.fetchone()

       if row is None:
          return None
       return dict(row._mapping)

def get_mitre_supporting_articles(
    technique_id,
    limit=20,
):
    if not isinstance(technique_id, str):
        raise ValueError(
            "MITRE technique ID must be a string."
        )

    normalized_technique_id = (
        technique_id.strip().upper()
    )

    if MITRE_TECHNIQUE_ID_PATTERN.fullmatch(
        normalized_technique_id
    ) is None:
        raise ValueError(
            "MITRE technique ID must follow "
            "the format TNNNN or TNNNN.NNN."
        )

    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or limit < 1
        or limit
        > MAX_MITRE_SUPPORTING_ARTICLE_LIMIT
    ):
        raise ValueError(
            "MITRE supporting article limit "
            "must be between 1 and 50."
        )

    query = text("""
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
                    WHEN jsonb_typeof(
                        article_analysis.mitre_techniques
                    ) = 'array'
                        THEN article_analysis.mitre_techniques
                    ELSE '[]'::jsonb
                END
            ) AS technique_value
            WHERE UPPER(technique_value)
                = :technique_id
        )
        ORDER BY
            articles.published DESC NULLS LAST,
            articles.id DESC
        LIMIT :limit;
    """)

    with engine.connect() as connection:
        rows = connection.execute(
            query,
            {
                "technique_id": (
                    normalized_technique_id
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
                if row.confidence_score
                is not None
                else None
            ),
        }
        for row in rows
    ]

    return {
        "technique_id": (
            normalized_technique_id
        ),
        "supporting_article_count": (
            supporting_article_count
        ),
        "articles": articles,
    }


if __name__ == "__main__":
    technique = get_mitre_technique_details("T1190")
    print(technique)
  
