from sqlalchemy import text
import json

from database.connection import engine


def insert_article(article):
  with engine.connect() as connection:
    query=text("""
    INSERT INTO articles (title, link, published, summary, source)
    VALUES (:title, :link, :published, :summary, :source)
    ON CONFLICT (link) DO UPDATE SET
      published = COALESCE(
        articles.published,
        EXCLUDED.published
      ),
      source = COALESCE(
        articles.source,
        EXCLUDED.source
      );
    """)
    connection.execute(query,{
      "title":article["title"],  
      "link":article["link"],
      "published":article["published"],
      "summary":article["summary"],
      "source" :article["source"],
    })
    connection.commit()

""" count the total number of articles in the database."""

def count_articles():
  with engine.connect() as connection:
    query=text("""SELECT COUNT(*) FROM articles;""")
    result =connection.execute(query)
    return result.scalar()


""" get the most recent articles from the database, limited by the specified number."""

def get_recent_articles(limit):
  with engine.connect() as connection:
    query = text("""
    SELECT * FROM articles 
    ORDER BY published DESC
    LIMIT :limit;
    """)
    result = connection.execute(query,{"limit":limit})
    return result.fetchall()

""" get unprocessed articles from the database, limited by the specified number."""

def get_unprocessed_articles(limit):
  with engine.connect() as connection:
    query = text("""
    SELECT id, title, link, published, summary 
    FROM articles
    WHERE processed = FALSE
    ORDER BY id ASC
    LIMIT :limit;
    """)
    result = connection.execute(query, {"limit": limit})
    return result.fetchall()

def _normalize_article_ids(article_ids):
  if not isinstance(article_ids, list):
    raise ValueError(
      "Article IDs must be provided as a list."
    )

  unique_article_ids = []
  seen_article_ids = set()

  for article_id in article_ids:
    if (
      not isinstance(article_id, int)
      or isinstance(article_id, bool)
      or article_id <= 0
    ):
      raise ValueError(
        "Each article ID must be a positive integer."
      )

    if article_id not in seen_article_ids:
      unique_article_ids.append(article_id)
      seen_article_ids.add(article_id)

  return unique_article_ids

def get_unprocessed_articles_by_ids(article_ids):
  unique_article_ids = (
    _normalize_article_ids(article_ids)
  )
  if not unique_article_ids:
    return []

  query = text("""
    SELECT
      id,
      title,
      link,
      published,
      summary
    FROM articles
    WHERE processed = FALSE
      AND id = ANY(
        CAST(:article_ids AS INTEGER[])
      )
    ORDER BY array_position(
      CAST(:article_ids AS INTEGER[]),
      id
    );
  """)

  with engine.connect() as connection:
    result = connection.execute(
      query,
      {
        "article_ids": unique_article_ids,
      },
    )

    return result.fetchall()

def get_articles_by_ids(article_ids):
  unique_article_ids = (
    _normalize_article_ids(article_ids)
  )

  if not unique_article_ids:
    return []

  query = text("""
    SELECT
      id,
      title,
      link,
      published,
      summary
    FROM articles
    WHERE id = ANY(
      CAST(:article_ids AS INTEGER[])
    )
    ORDER BY array_position(
      CAST(:article_ids AS INTEGER[]),
      id
    );
  """)

  with engine.connect() as connection:
    result = connection.execute(
      query,
      {
        "article_ids": unique_article_ids,
      },
    )

    return result.fetchall()


""" mark an article as processed in the database based on its ID."""

def mark_article_as_processed(article_id):
  with engine.connect() as connection:
    query = text("""
    UPDATE articles
    SET processed = True
    WHERE id =:article_id;
    """)
    result = connection.execute(query,{"article_id":article_id}) 
    connection.commit()

def save_article_analysis(analysis):
  with engine.connect() as connection:
    query = text("""
    INSERT INTO article_analysis(
    article_id,
    summary,
    classification,
    severity,
    confidence_score,
    iocs,
    cves,
    malware,
    mitre_techniques,
    apt_groups,
    targeted_sectors,
    affected_technologies
    )
    VALUES (
    :article_id,
    :summary,
    :classification,
    :severity,
    :confidence_score,
    :iocs,
    :cves,
    :malware,
    :mitre_techniques,
    :apt_groups,
    :targeted_sectors,
    :affected_technologies
    )
    ON CONFLICT (article_id)
    DO UPDATE SET
      summary = EXCLUDED.summary,
      classification = EXCLUDED.classification,
      severity = EXCLUDED.severity,
      confidence_score = EXCLUDED.confidence_score,
      iocs = EXCLUDED.iocs,
      cves = EXCLUDED.cves,
      malware = EXCLUDED.malware,
      mitre_techniques = EXCLUDED.mitre_techniques,
      apt_groups = EXCLUDED.apt_groups,
      targeted_sectors = EXCLUDED.targeted_sectors,
      affected_technologies = EXCLUDED.affected_technologies;
    """)
    connection.execute(query,{
      "article_id": analysis["article_id"],
      "summary":analysis["summary"],
      "classification":json.dumps(analysis["classification"]),
      "severity":analysis["severity"],
      "confidence_score":analysis["confidence_score"],
      "iocs":json.dumps(analysis["iocs"]),
      "cves":json.dumps(analysis["cves"]),
      "malware":json.dumps(analysis["malware"]),
      "mitre_techniques":json.dumps(analysis["mitre_techniques"]),
      "apt_groups": json.dumps(analysis["apt_groups"]),
      "targeted_sectors":json.dumps(analysis["targeted_sectors"]),
      "affected_technologies":json.dumps(analysis["affected_technologies"]) 
      })
    connection.commit()


def get_recent_analysis(limit):
  with engine.connect() as connection:
    query = text ("""
    SELECT * FROM article_analysis
    ORDER BY created_at DESC
    LIMIT :limit;
    """)
    result = connection.execute(query,{"limit": limit})
    return result.fetchall()

def search_articles(keyword):
  query=text(
    """
    SELECT
    articles.id AS article_id,
    articles.title,
    article_analysis.summary,
    article_analysis.severity,
    article_analysis.confidence_score,
    article_analysis.cves,
    article_analysis.malware,
    article_analysis.mitre_techniques
    FROM articles
    JOIN article_analysis
      ON articles.id=article_analysis.article_id
    WHERE articles.title ILIKE :keyword
      OR article_analysis.summary ILIKE :keyword
    ORDER BY articles.published DESC
      LIMIT 10
             
""")
  with engine.connect() as connection:
    result=connection.execute(
      query,
      {"keyword":f"%{keyword}%"}
    )
    rows=result.fetchall()
  
  articles = []
  for row in rows:
    articles.append({
      "article_id":row.article_id,
      "title":row.title,
      "summary":row.summary,
      "severity":row.severity,
      "confidence_score": float(row.confidence_score) if row.confidence_score is not None else None,
      "cves":row.cves,
      "malware":row.malware,
      "mitre_techniques":row.mitre_techniques
    })
  return articles

def get_article_details(article_id):
  query=text(
    """
    SELECT
      articles.id AS article_id,
      articles.title,
      articles.link,
      articles.published,
      article_analysis.summary,
      article_analysis.classification,
      article_analysis.severity,
      article_analysis.confidence_score,
      article_analysis.iocs,
      article_analysis.cves,
      article_analysis.malware,
      article_analysis.mitre_techniques,
      article_analysis.apt_groups,
      article_analysis.targeted_sectors,
      article_analysis.affected_technologies
    FROM articles
    JOIN article_analysis
      ON articles.id=article_analysis.article_id
    WHERE articles.id= :article_id
"""
  )
  with engine.connect() as connection:
    result = connection.execute(
      query,
      {"article_id":article_id}
    )
    row = result.fetchone()
    if row is None:
      return None
    
  return {
    "article_id":row.article_id,
    "title":row.title,
    "link":row.link,
    "published":row.published.isoformat() if row.published is not None else None,
    "summary" : row.summary,
    "classification":row.classification,
    "severity":row.severity,
    "confidence_score":(
      float(row.confidence_score)
      if row.confidence_score is not None
      else None
    ),
    "iocs":row.iocs,
    "cves":row.cves,
    "malware":row.malware,
    "mitre_techniques":row.mitre_techniques,
    "apt_groups":row.apt_groups,
    "targeted_sectors":row.targeted_sectors,
    "affected_technologies":row.affected_technologies,
  }

def get_articles_missing_publication_date(source,limit):
  query=text(
    """
    SELECT
      id,
      link,
      source
    FROM articles
    WHERE published IS NULL
    AND source = :source
    ORDER BY id ASC
    LIMIT :limit;
    """
  )
  with engine.connect() as connection:
    result=connection.execute(query,{"source":source,"limit":limit})
    rows= result.fetchall()

  return[
      {
        "article_id":row.id,
        "link":row.link,
        "source":row.source,
      }
      for row in rows
  ] 

def update_article_publication_date(article_id, published):
  query = text("""
    UPDATE articles
    SET published = :published
    WHERE id = :article_id
      AND published IS NULL;
  """)

  with engine.begin() as connection:
    result = connection.execute(
      query,
      {
        "article_id": article_id,
        "published": published,
      }
    )

  return result.rowcount == 1