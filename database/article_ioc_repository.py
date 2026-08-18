from sqlalchemy import text

from database.connection import engine


def save_article_ioc(
    article_id,
    indicator,
    indicator_type,
):
    query = text("""
        INSERT INTO article_iocs (
            article_id,
            indicator,
            indicator_type
        )
        VALUES (
            :article_id,
            :indicator,
            :indicator_type
        )
        ON CONFLICT (
            article_id,
            indicator,
            indicator_type
        )
        DO NOTHING;
    """)

    parameters = {
        "article_id": article_id,
        "indicator": indicator,
        "indicator_type": indicator_type,
    }

    with engine.begin() as connection:
        result = connection.execute(
            query,
            parameters,
        )

    return result.rowcount == 1

def get_article_iocs(article_id):
    query = text("""
        SELECT
            article_id,
            indicator,
            indicator_type,
            created_at
        FROM article_iocs
        WHERE article_id = :article_id
        ORDER BY indicator_type, indicator;
    """)

    with engine.connect() as connection:
        result = connection.execute(
            query,
            {"article_id": article_id},
        )

        rows = result.fetchall()

    return [
        {
            "article_id": row.article_id,
            "indicator": row.indicator,
            "indicator_type": row.indicator_type,
            "created_at": row.created_at.isoformat(),
        }
        for row in rows
    ]

def replace_article_iocs(article_id, iocs):
    if (
        not isinstance(article_id, int)
        or isinstance(article_id, bool)
        or article_id <= 0
    ):
        raise ValueError(
            "Article ID must be a positive integer."
        )

    if not isinstance(iocs, list):
        raise ValueError(
            "IOCs must be provided as a list."
        )

    parameters = []

    for ioc in iocs:
        if not isinstance(ioc, dict):
            raise ValueError(
                "Each IOC must be a dictionary."
            )

        indicator = ioc.get("indicator")
        indicator_type = ioc.get("indicator_type")

        if not isinstance(indicator, str) or not indicator.strip():
            raise ValueError(
                "Each IOC must contain a non-empty indicator."
            )

        if (
            not isinstance(indicator_type, str)
            or not indicator_type.strip()
        ):
            raise ValueError(
                "Each IOC must contain a non-empty indicator type."
            )

        parameters.append({
            "article_id": article_id,
            "indicator": indicator,
            "indicator_type": indicator_type,
        })

    delete_query = text("""
        DELETE FROM article_iocs
        WHERE article_id = :article_id;
    """)

    insert_query = text("""
        INSERT INTO article_iocs (
            article_id,
            indicator,
            indicator_type
        )
        VALUES (
            :article_id,
            :indicator,
            :indicator_type
        )
        ON CONFLICT (
            article_id,
            indicator,
            indicator_type
        )
        DO NOTHING;
    """)

    with engine.begin() as connection:
        delete_result = connection.execute(
            delete_query,
            {"article_id": article_id},
        )

        inserted_count = 0

        if parameters:
            insert_result = connection.execute(
                insert_query,
                parameters,
            )

            inserted_count = insert_result.rowcount

    return {
        "article_id": article_id,
        "deleted_count": delete_result.rowcount,
        "inserted_count": inserted_count,
    }