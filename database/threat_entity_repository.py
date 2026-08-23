from sqlalchemy import text

from database.connection import engine


MAX_ENTITY_SEARCH_LIMIT = 50
MAX_ENTITY_KEYWORD_LENGTH = 200
MAX_ENTITY_VALUE_LENGTH = 500

ENTITY_COLUMN_MAP = {
    "malware": "malware",
    "apt_group": "apt_groups",
    "targeted_sector": "targeted_sectors",
    "affected_technology": (
        "affected_technologies"
    ),
}


def _get_entity_column(entity_type):
    if not isinstance(entity_type, str):
        raise ValueError(
            "Entity type must be a string."
        )

    normalized_entity_type = (
        entity_type.strip().lower()
    )

    column_name = ENTITY_COLUMN_MAP.get(
        normalized_entity_type
    )

    if column_name is None:
        raise ValueError(
            "Entity type must be one of: "
            "malware, apt_group, targeted_sector, "
            "affected_technology."
        )

    return normalized_entity_type, column_name


def _normalize_required_text(
    value,
    label,
    maximum_length,
):
    if not isinstance(value, str):
        raise ValueError(
            f"{label} must be a string."
        )

    normalized_value = value.strip()

    if not normalized_value:
        raise ValueError(
            f"{label} cannot be empty."
        )

    if len(normalized_value) > maximum_length:
        raise ValueError(
            f"{label} cannot exceed "
            f"{maximum_length} characters."
        )

    return normalized_value


def _validate_limit(limit):
    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or limit < 1
        or limit > MAX_ENTITY_SEARCH_LIMIT
    ):
        raise ValueError(
            "Entity search limit must be an "
            "integer between 1 and 50."
        )


def _validate_offset(offset):
    if (
        not isinstance(offset, int)
        or isinstance(offset, bool)
        or offset < 0
    ):
        raise ValueError(
            "Entity search offset must be a "
            "non-negative integer."
        )


def _safe_json_array(value):
    if isinstance(value, list):
        return value

    return []


def _serialize_datetime(value):
    if value is None:
        return None

    return value.isoformat()


def search_threat_entity_values(
    entity_type,
    keyword,
    limit=10,
    offset=0,
):
    (
        normalized_entity_type,
        column_name,
    ) = _get_entity_column(entity_type)

    normalized_keyword = _normalize_required_text(
        keyword,
        "Entity search keyword",
        MAX_ENTITY_KEYWORD_LENGTH,
    )

    _validate_limit(limit)
    _validate_offset(offset)

    query = text(
        f"""
        WITH extracted_entities AS (
            SELECT
                articles.id AS article_id,
                articles.published,
                entity_value
            FROM articles
            JOIN article_analysis
                ON article_analysis.article_id
                    = articles.id
            CROSS JOIN LATERAL
                jsonb_array_elements_text(
                    CASE
                        WHEN jsonb_typeof(
                            article_analysis.{column_name}
                        ) = 'array'
                        THEN article_analysis.{column_name}
                        ELSE '[]'::jsonb
                    END
                ) AS extracted(entity_value)
        )
        SELECT
            MIN(entity_value) AS value,
            COUNT(DISTINCT article_id)
                AS supporting_article_count,
            MAX(published) AS latest_seen
        FROM extracted_entities
        WHERE entity_value ILIKE :keyword
        GROUP BY LOWER(entity_value)
        ORDER BY
            supporting_article_count DESC,
            latest_seen DESC NULLS LAST,
            LOWER(MIN(entity_value)) ASC
        LIMIT :limit
        OFFSET :offset;
        """
    )

    with engine.connect() as connection:
        rows = connection.execute(
            query,
            {
                "keyword": (
                    f"%{normalized_keyword}%"
                ),
                "limit": limit,
                "offset": offset,
            },
        ).fetchall()

    return {
        "entity_type": normalized_entity_type,
        "keyword": normalized_keyword,
        "limit": limit,
        "offset": offset,
        "returned_count": len(rows),
        "results": [
            {
                "value": row.value,
                "supporting_article_count": (
                    row.supporting_article_count
                ),
                "latest_seen": _serialize_datetime(
                    row.latest_seen
                ),
            }
            for row in rows
        ],
    }


def get_threat_entity_evidence(
    entity_type,
    value,
    limit=20,
):
    (
        normalized_entity_type,
        column_name,
    ) = _get_entity_column(entity_type)

    normalized_value = _normalize_required_text(
        value,
        "Entity value",
        MAX_ENTITY_VALUE_LENGTH,
    )

    _validate_limit(limit)

    query = text(
        f"""
        SELECT
            articles.id AS article_id,
            articles.title,
            articles.link,
            articles.source,
            articles.published,
            article_analysis.summary,
            article_analysis.severity,
            article_analysis.confidence_score,
            article_analysis.cves,
            article_analysis.malware,
            article_analysis.mitre_techniques,
            article_analysis.apt_groups,
            article_analysis.targeted_sectors,
            article_analysis.affected_technologies,
            COUNT(*) OVER()
                AS supporting_article_count
        FROM articles
        JOIN article_analysis
            ON article_analysis.article_id
                = articles.id
        WHERE EXISTS (
            SELECT 1
            FROM jsonb_array_elements_text(
                CASE
                    WHEN jsonb_typeof(
                        article_analysis.{column_name}
                    ) = 'array'
                    THEN article_analysis.{column_name}
                    ELSE '[]'::jsonb
                END
            ) AS extracted(entity_value)
            WHERE LOWER(entity_value)
                = LOWER(:value)
        )
        ORDER BY
            articles.published DESC NULLS LAST,
            articles.id DESC
        LIMIT :limit;
        """
    )

    with engine.connect() as connection:
        rows = connection.execute(
            query,
            {
                "value": normalized_value,
                "limit": limit,
            },
        ).fetchall()

    articles = [
        {
            "article_id": row.article_id,
            "title": row.title,
            "link": row.link,
            "source": row.source,
            "published": _serialize_datetime(
                row.published
            ),
            "summary": row.summary,
            "severity": row.severity,
            "confidence_score": (
                float(row.confidence_score)
                if row.confidence_score is not None
                else None
            ),
            "cves": _safe_json_array(row.cves),
            "malware": _safe_json_array(
                row.malware
            ),
            "mitre_techniques": _safe_json_array(
                row.mitre_techniques
            ),
            "apt_groups": _safe_json_array(
                row.apt_groups
            ),
            "targeted_sectors": _safe_json_array(
                row.targeted_sectors
            ),
            "affected_technologies": (
                _safe_json_array(
                    row.affected_technologies
                )
            ),
        }
        for row in rows
    ]

    supporting_article_count = (
        rows[0].supporting_article_count
        if rows
        else 0
    )

    return {
        "entity_type": normalized_entity_type,
        "value": normalized_value,
        "limit": limit,
        "supporting_article_count": (
            supporting_article_count
        ),
        "returned_count": len(articles),
        "articles": articles,
    }