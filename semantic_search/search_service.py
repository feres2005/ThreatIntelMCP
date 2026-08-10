from database.embedding_repository import search_article_embeddings
from semantic_search.embedding_service import EMBEDDING_MODEL_NAME, generate_embedding

MAX_SEARCH_RESULTS = 50

def semantic_search_articles(search_query, limit=10):
  if not isinstance(search_query,str)or not search_query.strip():
    raise ValueError("Search query must be a non-empty string.")

  if(not isinstance(limit,int)or isinstance(limit,bool)or limit<=0 or limit>MAX_SEARCH_RESULTS ):
    raise ValueError(f"Limit must be between 1 and {MAX_SEARCH_RESULTS}.")

  query_embedding = generate_embedding(search_query, "query")

  return search_article_embeddings(query_embedding=query_embedding, embedding_model=EMBEDDING_MODEL_NAME, limit=limit)
