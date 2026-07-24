from sqlalchemy import text

from database.connection import engine

def search_malware(keyword):
  query=text(
    """
    SELECT
      articles.id AS article_id,
      articles.title,
      article_analysis.summary,
      article_analysis.severity,
      article_analysis.confidence_score,
      article_analysis.malware,
      article_analysis.cves,
      article_analysis.mitre_techniques
      FROM articles
      JOIN article_analysis
        ON articles.id = article_analysis.article_id
      WHERE EXISTS(
        SELECT 1
        FROM jsonb_array_elements_text(article_analysis.malware) AS malware_name
        WHERE malware_name ILIKE :keyword
      )
      ORDER BY articles.published DESC
      LIMIT 10;
"""
  )
  with engine.connect() as connection:
    result=connection.execute(
      query,
      {"keyword": f"%{keyword}%"}
    )
    rows =result.fetchall()
  articles=[]

  for row in rows :
    articles.append({
      "article_id":row.article_id,
      "title":row.title,
      "summary":row.summary,
      "severity":row.severity,
      "confidence_score":(
        float(row.confidence_score)
        if row.confidence_score is not None
        else None
      ),
      "malware":row.malware,
      "cves":row.cves,
      "mitre_techniques":row.mitre_techniques
    })
  return articles


def search_mitre(keyword):
  query=text(
    """
    SELECT
      articles.id AS article_id,
      articles.title,
      article_analysis.summary,
      article_analysis.severity,
      article_analysis.confidence_score,
      article_analysis.malware,
      article_analysis.cves,
      article_analysis.mitre_techniques
      FROM articles
      JOIN article_analysis
        ON articles.id = article_analysis.article_id
      WHERE EXISTS(
        SELECT 1
        FROM jsonb_array_elements_text(article_analysis.mitre_techniques) AS malware_name
        WHERE malware_name ILIKE :keyword
      )
      ORDER BY articles.published DESC
      LIMIT 10;
"""
  )
  with engine.connect() as connection:
    result=connection.execute(
      query,
      {"keyword": f"%{keyword}%"}
    )
    rows =result.fetchall()
  articles=[]

  for row in rows :
    articles.append({
      "article_id":row.article_id,
      "title":row.title,
      "summary":row.summary,
      "severity":row.severity,
      "confidence_score":(
        float(row.confidence_score)
        if row.confidence_score is not None
        else None
      ),
      "malware":row.malware,
      "cves":row.cves,
      "mitre_techniques":row.mitre_techniques
    })
  return articles

def search_apt_groups(keyword):
  query = text(
    """
    SELECT
      articles.id AS article_id,
      articles.title,
      article_analysis.summary,
      article_analysis.severity,
      article_analysis.confidence_score,
      article_analysis.apt_groups,
      article_analysis.cves,
      article_analysis.malware,
      article_analysis.mitre_techniques
    FROM articles
    JOIN article_analysis
      ON articles.id = article_analysis.article_id
    WHERE EXISTS (
      SELECT 1
      FROM jsonb_array_elements_text(
      CASE
        WHEN jsonb_typeof(article_analysis.apt_groups) = 'array'
          THEN article_analysis.apt_groups
        ELSE '[]'::jsonb
      END
      ) AS apt_group_name
      WHERE apt_group_name ILIKE :keyword
    )
    ORDER BY articles.published DESC
    LIMIT 10;
    """
  )

  with engine.connect() as connection:
    result = connection.execute(
      query,
      {"keyword": f"%{keyword}%"}
    )
    rows = result.fetchall()

  articles = []

  for row in rows:
    articles.append({
      "article_id": row.article_id,
      "title": row.title,
      "summary": row.summary,
      "severity": row.severity,
      "confidence_score": (
        float(row.confidence_score)
        if row.confidence_score is not None
        else None
      ),
      "apt_groups": row.apt_groups,
      "cves": row.cves,
      "malware": row.malware,
      "mitre_techniques": row.mitre_techniques
    })

  return articles

def search_targeted_sectors(keyword):
  query = text(
    """
    SELECT
      articles.id AS article_id,
      articles.title,
      article_analysis.summary,
      article_analysis.severity,
      article_analysis.confidence_score,
      article_analysis.targeted_sectors,
      article_analysis.cves,
      article_analysis.malware,
      article_analysis.mitre_techniques
    FROM articles
    JOIN article_analysis
      ON articles.id = article_analysis.article_id
    WHERE EXISTS (
      SELECT 1
      FROM jsonb_array_elements_text(
        article_analysis.targeted_sectors
      ) AS targeted_sectors_name
      WHERE targeted_sectors_name ILIKE :keyword
    )
    ORDER BY articles.published DESC
    LIMIT 10;
    """
  )

  with engine.connect() as connection:
    result = connection.execute(
      query,
      {"keyword": f"%{keyword}%"}
    )
    rows = result.fetchall()

  articles = []

  for row in rows:
    articles.append({
      "article_id": row.article_id,
      "title": row.title,
      "summary": row.summary,
      "severity": row.severity,
      "confidence_score": (
        float(row.confidence_score)
        if row.confidence_score is not None
        else None
      ),
      "targeted_sectors": row.targeted_sectors,
      "cves": row.cves,
      "malware": row.malware,
      "mitre_techniques": row.mitre_techniques
    })

  return articles 


def search_affected_technologies(keyword):
  query = text(
    """
    SELECT
      articles.id AS article_id,
      articles.title,
      article_analysis.summary,
      article_analysis.severity,
      article_analysis.confidence_score,
      article_analysis.affected_technologies,
      article_analysis.cves,
      article_analysis.malware,
      article_analysis.mitre_techniques
    FROM articles
    JOIN article_analysis
      ON articles.id = article_analysis.article_id
    WHERE EXISTS (
      SELECT 1
      FROM jsonb_array_elements_text(
        article_analysis.affected_technologies
      ) AS affected_technologies_name
      WHERE affected_technologies_name ILIKE :keyword
    )
    ORDER BY articles.published DESC
    LIMIT 10;
    """
  )

  with engine.connect() as connection:
    result = connection.execute(
      query,
      {"keyword": f"%{keyword}%"}
    )
    rows = result.fetchall()

  articles = []

  for row in rows:
    articles.append({
      "article_id": row.article_id,
      "title": row.title,
      "summary": row.summary,
      "severity": row.severity,
      "confidence_score": (
        float(row.confidence_score)
        if row.confidence_score is not None
        else None
      ),
      "affected_technologies": row.affected_technologies,
      "cves": row.cves,
      "malware": row.malware,
      "mitre_techniques": row.mitre_techniques
    })

  return articles 

