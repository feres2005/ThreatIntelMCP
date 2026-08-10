
import math
from sqlalchemy import text
from database.connection import engine

EMBEDDING_DIMENSIONS = 384

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
            "similarity": float(row.similarity),
        }
        for row in rows
    ]
