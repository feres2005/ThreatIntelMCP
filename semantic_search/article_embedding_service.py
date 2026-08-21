from database.embedding_repository import (get_article_for_embedding,save_intelligence_embedding,get_articles_without_embeddings)
from semantic_search.article_content import (build_article_passage,calculate_content_hash)
from semantic_search.embedding_service import (EMBEDDING_MODEL_NAME,generate_embedding)


def index_article(article_id):
    article = get_article_for_embedding(article_id)

    if article is None:
        return {
            "article_id": article_id,
            "status": "not_found",
        }

    return _index_article_data(article)


#helper function to index multiple articles
def _index_article_data(article):
    article_id = article["article_id"]

    passage = build_article_passage(
        article["title"],
        article["rss_summary"],
        article["ai_summary"],
    )
    content_hash = calculate_content_hash(passage)

    content_unchanged = (
        article["existing_content_hash"] == content_hash
    )
    model_unchanged = (
        article["existing_embedding_model"] == EMBEDDING_MODEL_NAME
    )

    if content_unchanged and model_unchanged:
        return {
            "article_id": article_id,
            "status": "unchanged",
        }

    embedding = generate_embedding(passage, "passage")

    saved = save_intelligence_embedding(
        entity_type="article",
        entity_id=article_id,
        embedding=embedding,
        embedding_model=EMBEDDING_MODEL_NAME,
        content_hash=content_hash,
    )

    if not saved:
        status = "unchanged"
    elif article["existing_content_hash"] is None:
        status = "created"
    else:
        status = "updated"

    return {
        "article_id": article_id,
        "status": status,
    }

def index_missing_articles(limit):
  articles=get_articles_without_embeddings(limit)
  results= []
  for article in articles:

    try:
      result = _index_article_data(article)
    except Exception as error:
      result = {
        "article_id": article.get("article_id"),
        "status": "failed",
        "error": (
          f"{type(error).__name__}: "
          f"{error}"
        ),
      }

    results.append(result)
  return results
