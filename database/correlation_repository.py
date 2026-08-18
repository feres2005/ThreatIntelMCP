from database.article_repository import get_article_details
from database.article_ioc_repository import get_article_iocs
from sqlalchemy import text

from database.connection import engine

def get_article_correlation_data(article_id):
    article = get_article_details(article_id)

    if article is None:
        return None

    return {
        "article": article,
        "typed_iocs": get_article_iocs(article_id),
    }


def get_article_ids_by_indicator(
    indicator,
    indicator_type,
):
    query = text("""
        SELECT article_id
        FROM article_iocs
        WHERE indicator = :indicator
          AND indicator_type = :indicator_type
        ORDER BY article_id;
    """)

    with engine.connect() as connection:
        article_ids = connection.execute(
            query,
            {
                "indicator": indicator,
                "indicator_type": indicator_type,
            },
        ).scalars().all()

    return list(article_ids)