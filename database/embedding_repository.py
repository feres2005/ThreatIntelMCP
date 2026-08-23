from datetime import datetime
import math
from sqlalchemy import text
from database.connection import engine
import json
EMBEDDING_DIMENSIONS = 384
MAX_TOPIC_MODELING_ARTICLES = 500

def serialize_embedding(embedding):
   if not isinstance(embedding,(list,tuple)):
      raise ValueError("Embedding must be a list or tuple")
   if len(embedding) != EMBEDDING_DIMENSIONS:
      raise ValueError("Embedding must contain exactly 384 elements")

   if not all(
      isinstance(value,(float,int))and not isinstance (value,bool) and math.isfinite(value) for value in embedding
   ):
      raise ValueError("All elements in the embedding must be finite numbers")
   return "["+",".join(str(value)for value in embedding)+"]"

def _deserialize_stored_embedding(value):
    error_message = (
        "Stored embedding must contain exactly "
        "384 finite numbers."
    )

    if not isinstance(value, str):
        raise ValueError(error_message)

    try:
        embedding = json.loads(value)
    except (TypeError, ValueError) as error:
        raise ValueError(error_message) from error

    if (
        not isinstance(embedding, list)
        or len(embedding) != EMBEDDING_DIMENSIONS
        or not all(
            isinstance(item, (int, float))
            and not isinstance(item, bool)
            and math.isfinite(item)
            for item in embedding
        )
    ):
        raise ValueError(error_message)

    return [
        float(item)
        for item in embedding
    ]


def _normalize_optional_list(value):
    if not isinstance(value, list):
        return []

    return list(value)

def get_articles_without_embeddings(limit):
  if not isinstance(limit, int) or isinstance(limit,bool) or limit<=0:
    raise ValueError("Limit must be a positive integer")

  query=text("""
    SELECT
      articles.id AS article_id,
      articles.title,
      articles.summary AS rss_summary,
      article_analysis.summary AS ai_summary

    FROM articles
    LEFT JOIN article_analysis ON articles.id = article_analysis.article_id
    LEFT JOIN intelligence_embeddings ON intelligence_embeddings.entity_type = 'article'
    AND intelligence_embeddings.entity_id = articles.id::text
    WHERE intelligence_embeddings.entity_id IS NULL
    ORDER BY articles.id ASC

    LIMIT :limit
      """)

  with engine.connect() as connection:
    result=connection.execute(query,{"limit":limit})
    rows=result.fetchall()

  return[
    {
    "article_id":row.article_id,
    "title":row.title,
    "rss_summary":row.rss_summary,
    "ai_summary":row.ai_summary,
    "existing_content_hash": None,
    "existing_embedding_model": None
    }
    for row in rows

  ]

def save_intelligence_embedding(entity_type,entity_id,embedding,embedding_model,content_hash):
   if not isinstance(entity_type,str) or not entity_type.strip():
      raise ValueError("Entity type must be a non-empty string")

   if entity_id is None or not str(entity_id).strip():
      raise ValueError("Entity ID must be  non-empty ")

   if not isinstance(embedding_model,str)or not embedding_model.strip():
      raise ValueError("Embedding model must be a non-empty string")

   if not isinstance(content_hash,str)or not content_hash.strip():
      raise ValueError("Content hash must be a non-empty string")

   serialized_embedding=serialize_embedding(embedding)

   query = text("""
      INSERT INTO intelligence_embeddings (entity_type, entity_id, embedding, embedding_model, content_hash)
      VALUES (:entity_type, :entity_id, CAST(:embedding AS vector), :embedding_model, :content_hash)
      ON CONFLICT (entity_type, entity_id) DO UPDATE SET
        embedding = EXCLUDED.embedding,
        embedding_model = EXCLUDED.embedding_model,
        content_hash = EXCLUDED.content_hash,
        embedded_at = CURRENT_TIMESTAMP
      WHERE intelligence_embeddings.content_hash IS DISTINCT FROM EXCLUDED.content_hash
      OR intelligence_embeddings.embedding_model IS DISTINCT FROM EXCLUDED.embedding_model;

      """)

   with engine.begin() as connection:
      result=connection.execute(
         query,
         {
            "entity_type": entity_type.strip(),
            "entity_id": str(entity_id).strip(),
            "embedding": serialized_embedding,
            "embedding_model": embedding_model.strip(),
            "content_hash": content_hash.strip()
         },
      )

   return result.rowcount==1

def get_article_for_embedding(article_id):
    if (
        not isinstance(article_id, int)
        or isinstance(article_id, bool)
        or article_id <= 0
    ):
        raise ValueError("Article ID must be a positive integer.")

    query = text("""
        SELECT
            articles.id AS article_id,
            articles.title,
            articles.summary AS rss_summary,
            article_analysis.summary AS ai_summary,
            intelligence_embeddings.content_hash AS existing_content_hash,
            intelligence_embeddings.embedding_model AS existing_embedding_model
        FROM articles
        LEFT JOIN article_analysis
            ON article_analysis.article_id = articles.id

        LEFT JOIN intelligence_embeddings
          ON intelligence_embeddings.entity_type = 'article'
          AND intelligence_embeddings.entity_id = articles.id::text
        WHERE articles.id = :article_id;
    """)

    with engine.connect() as connection:
        result = connection.execute(
            query,
            {"article_id": article_id},
        )
        row = result.fetchone()

    if row is None:
        return None

    return {
        "article_id": row.article_id,
        "title": row.title,
        "rss_summary": row.rss_summary,
        "ai_summary": row.ai_summary,
        "existing_content_hash": row.existing_content_hash,
        "existing_embedding_model": row.existing_embedding_model,
    }


def search_article_embeddings(query_embedding, embedding_model, limit):
    if not isinstance(embedding_model, str) or not embedding_model.strip():
        raise ValueError("Embedding model must be a non-empty string.")

    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        raise ValueError("Limit must be a positive integer.")

    serialized_query = serialize_embedding(query_embedding)

    query = text("""
        SELECT
            articles.id AS article_id,
            articles.title,
            articles.link,
            articles.source,
            articles.published,
            COALESCE(
                article_analysis.summary,
                articles.summary
            ) AS summary,
            (
                article_analysis.article_id IS NOT NULL
            ) AS analysis_available,
            1 - (
                intelligence_embeddings.embedding
                <=> CAST(:query_embedding AS vector)
            ) AS similarity
        FROM intelligence_embeddings
        JOIN articles
            ON intelligence_embeddings.entity_type = 'article'
            AND intelligence_embeddings.entity_id = articles.id::text
        LEFT JOIN article_analysis
            ON article_analysis.article_id = articles.id
        WHERE intelligence_embeddings.embedding_model = :embedding_model
        ORDER BY
            intelligence_embeddings.embedding
            <=> CAST(:query_embedding AS vector)
        ASC
        LIMIT :limit;
    """)

    with engine.connect() as connection:
        result = connection.execute(
            query,
            {
                "query_embedding": serialized_query,
                "embedding_model": embedding_model.strip(),
                "limit": limit,
            },
        )
        rows = result.fetchall()

    return [
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
            "summary": row.summary,
            "analysis_available": bool(
                row.analysis_available
            ),
            "similarity": float(row.similarity),
        }
        for row in rows
    ]

def get_topic_modeling_articles(
    published_after,
    embedding_model,
    limit,
):
    if (
        not isinstance(published_after, datetime)
        or published_after.tzinfo is None
        or published_after.utcoffset() is None
    ):
        raise ValueError(
            "Published-after time must be timezone-aware."
        )

    if (
        not isinstance(embedding_model, str)
        or not embedding_model.strip()
    ):
        raise ValueError(
            "Embedding model must be a non-empty string."
        )

    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or limit <= 0
        or limit > MAX_TOPIC_MODELING_ARTICLES
    ):
        raise ValueError(
            "Limit must be between 1 and 500."
        )

    query = text("""
        SELECT
            articles.id AS article_id,
            articles.title,
            articles.link,
            articles.source,
            articles.published,
            COALESCE(
                article_analysis.summary,
                articles.summary
            ) AS summary,
            article_analysis.classification,
            article_analysis.severity,
            article_analysis.confidence_score,
            article_analysis.cves,
            article_analysis.malware,
            article_analysis.mitre_techniques,
            article_analysis.apt_groups,
            article_analysis.targeted_sectors,
            article_analysis.affected_technologies,
            CAST(
                intelligence_embeddings.embedding
                AS text
            ) AS embedding_text
        FROM intelligence_embeddings
        JOIN articles
          ON intelligence_embeddings.entity_type = 'article'
         AND intelligence_embeddings.entity_id
             = articles.id::text
        LEFT JOIN article_analysis
          ON article_analysis.article_id = articles.id
        WHERE articles.published IS NOT NULL
          AND articles.published >= :published_after
          AND articles.published <= CURRENT_TIMESTAMP
          AND intelligence_embeddings.embedding_model
              = :embedding_model
        ORDER BY articles.published DESC,
                 articles.id DESC
        LIMIT :limit;
    """)

    with engine.connect() as connection:
        result = connection.execute(
            query,
            {
                "published_after": published_after,
                "embedding_model": (
                    embedding_model.strip()
                ),
                "limit": limit,
            },
        )
        rows = result.fetchall()

    return [
        {
            "article_id": row.article_id,
            "title": row.title,
            "link": row.link,
            "source": row.source,
            "published": row.published,
            "summary": row.summary,
            "classification": (
                _normalize_optional_list(
                    row.classification
                )
            ),
            "severity": row.severity,
            "confidence_score": (
                float(row.confidence_score)
                if row.confidence_score is not None
                else None
            ),
            "cves": _normalize_optional_list(
                row.cves
            ),
            "malware": _normalize_optional_list(
                row.malware
            ),
            "mitre_techniques": (
                _normalize_optional_list(
                    row.mitre_techniques
                )
            ),
            "apt_groups": _normalize_optional_list(
                row.apt_groups
            ),
            "targeted_sectors": (
                _normalize_optional_list(
                    row.targeted_sectors
                )
            ),
            "affected_technologies": (
                _normalize_optional_list(
                    row.affected_technologies
                )
            ),
            "embedding": (
                _deserialize_stored_embedding(
                    row.embedding_text
                )
            ),
        }
        for row in rows
    ]
