from sqlalchemy import text
from database.connection import engine
import json
MAX_MITRE_SEARCH_LIMIT = 50
MAX_MITRE_SEARCH_KEYWORD_LENGTH = 200

SUPPORTED_MITRE_DOMAINS = {
    "enterprise-attack",
    "mobile-attack",
    "ics-attack",
}

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


if __name__ == "__main__":
    technique = get_mitre_technique_details("T1190")
    print(technique)
  
