from sqlalchemy import text
from database.connection import engine
import json


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


def search_mitre_techniques(keyword):
  query=text(
  """
  SELECT
    technique_id,
    name,
    domain,
    is_subtechnique,
    version
  FROM mitre_techniques
  WHERE technique_id ILIKE :keyword
    OR name ILIKE :keyword
  ORDER BY technique_id
  LIMIT 10
""")
  parameters= {"keyword":f"%{keyword}%"}
  with engine.connect() as connection:
    result=connection.execute(query,parameters)
    return [dict(row._mapping) for row in result]


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
  
