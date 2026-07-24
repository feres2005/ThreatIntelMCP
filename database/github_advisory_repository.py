from sqlalchemy import text
import json

from database.connection import engine


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


def search_github_advisories(keyword):
  query=text(
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
    WHERE ghsa_id ILIKE :keyword
      OR cve_id ILIKE :keyword
      OR summary ILIKE :keyword
      OR severity ILIKE :keyword
    ORDER BY published_at DESC
    LIMIT 10;
  """)
  with engine.connect() as connection:
    result= connection.execute(
      query,
      {"keyword":f"%{keyword}%"}
    )
    rows=result.fetchall()
  advisories=[]

  for row in rows:
    advisories.append({
      "ghsa_id":row.ghsa_id,
      "cve_id":row.cve_id,
      "summary":row.summary,
      "severity":row.severity,
      "published_at":(
        row.published_at.isoformat()
        if row.published_at is not None
        else None
      ),
      "updated_at":(
        row.updated_at.isoformat()
        if row.updated_at is not None
        else None
      ),
      "cvss_v3_score":(
        float(row.cvss_v3_score)
        if row.cvss_v3_score is not None
        else None
      ),
      "cvss_v4_score":(
        float(row.cvss_v4_score)
        if row.cvss_v4_score is not None
        else None
      )
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
