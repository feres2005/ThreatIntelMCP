import json 
from datetime import datetime
from sqlalchemy import text
from database.connection import engine

def save_otx_indicator(indicator_data):
    query=text(
      """
      INSERT INTO otx_indicators(
        indicator,
        indicator_type,
        reputation,
        pulse_count,
        country,
        country_code,
        asn,
        malware_families,
        adversaries,
        industries,
        validation,
        sections,
        last_checked
      ) 
      VALUES(
        :indicator,
        :indicator_type,
        :reputation,
        :pulse_count,
        :country,
        :country_code,
        :asn,
        CAST(:malware_families AS JSONB),
        CAST(:adversaries AS JSONB),
        CAST(:industries AS JSONB),
        CAST(:validation AS JSONB),
        CAST(:sections AS JSONB),
        CURRENT_TIMESTAMP
      )
      ON CONFLICT (indicator, indicator_type)
      DO UPDATE SET
        reputation = EXCLUDED.reputation,
        pulse_count = EXCLUDED.pulse_count,
        country = EXCLUDED.country,
        country_code = EXCLUDED.country_code,
        asn = EXCLUDED.asn,
        malware_families = EXCLUDED.malware_families,
        adversaries = EXCLUDED.adversaries,
        industries = EXCLUDED.industries,
        validation = EXCLUDED.validation,
        sections = EXCLUDED.sections,
        last_checked = CURRENT_TIMESTAMP;
""")

    parameters = {
        "indicator": indicator_data["indicator"],
        "indicator_type": indicator_data["indicator_type"],
        "reputation": indicator_data.get("reputation"),
        "pulse_count": indicator_data.get("pulse_count", 0),
        "country": indicator_data.get("country"),
        "country_code": indicator_data.get("country_code"),
        "asn": indicator_data.get("asn"),
        "malware_families": json.dumps(
            indicator_data.get("malware_families", [])
        ),
        "adversaries": json.dumps(
            indicator_data.get("adversaries", [])
        ),
        "industries": json.dumps(
            indicator_data.get("industries", [])
        ),
        "validation": json.dumps(
            indicator_data.get("validation", [])
        ),
        "sections": json.dumps(
            indicator_data.get("sections", [])
        ),
    }

    with engine.begin() as connection:
        connection.execute(query, parameters)


def search_otx_indicators(keyword:str,limit:int=10):
    query=text(
        """
        SELECT 
          indicator,
          indicator_type,
          reputation,
          pulse_count,
          country,
          country_code,
          asn,
          malware_families,
          adversaries,
          industries,
          last_checked
        FROM otx_indicators
        WHERE
          indicator ILIKE :keyword
          OR indicator_TYPE ILIKE :keyword
          OR country ILIKE :keyword
          OR country_code ILIKE :keyword
          OR asn ILIKE :keyword
        ORDER BY 
          pulse_count DESC,
          last_checked DESC
        LIMIT :limit;
""")
    parameters={
        "keyword":f"%{keyword}%",
        "limit":limit,
    }
    with engine.connect() as connection:
        result =connection.execute(query,parameters)
        return [dict(row._mapping) for row in result]


def get_otx_indicator_details(indicator: str,indicator_type: str):
    query=text(
        """
        SELECT 
          indicator,
          indicator_type,
          reputation,
          pulse_count,
          country,
          country_code,
          asn,
          malware_families,
          adversaries,
          industries,
          validation,
          sections,
          last_checked
        FROM otx_indicators
        WHERE
          indicator =:indicator
          AND indicator_type=:indicator_type;
""")
    parameters={
        "indicator":indicator,
        "indicator_type":indicator_type,
    }
    with engine.connect() as connection:
        result=connection.execute(query,parameters)
        row=result.fetchone()
        if row is None:
            return None
        return dict(row._mapping)


def get_otx_last_checked(
    indicator: str,
    indicator_type: str,
):
    query = text("""
        SELECT
            last_checked
        FROM otx_indicators
        WHERE
            indicator = :indicator
            AND indicator_type = :indicator_type;
    """)

    parameters = {
        "indicator": indicator,
        "indicator_type": indicator_type,
    }

    with engine.connect() as connection:
        result = connection.execute(
            query,
            parameters,
        )

        row = result.fetchone()

        if row is None:
            return None

        return row.last_checked

if __name__ == "__main__":
    search_results = search_otx_indicators(
        "Google"
    )

    print("Search results:")
    print(search_results)

    details = get_otx_indicator_details(
        "1.2.3.4",
        "IPv4",
    )

    print("\nIndicator details:")
    print(details)