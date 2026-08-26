import json

from sqlalchemy import text

from database.connection import engine


VIRUSTOTAL_COUNT_FIELDS = (
    "malicious_count",
    "suspicious_count",
    "harmless_count",
    "undetected_count",
    "timeout_count",
    "failure_count",
    "type_unsupported_count",
    "confirmed_timeout_count",
    "total_engine_count",
    "total_result_count",
)

VIRUSTOTAL_JSON_FIELDS = (
    "community_votes",
    "detections",
    "categories",
    "tags",
    "names",
)


def save_virustotal_indicator(
    indicator_data,
):
    query = text(
        """
        INSERT INTO virustotal_indicators (
            indicator,
            indicator_type,
            report_available,
            resource_type,
            resource_id,
            malicious_count,
            suspicious_count,
            harmless_count,
            undetected_count,
            timeout_count,
            failure_count,
            type_unsupported_count,
            confirmed_timeout_count,
            total_engine_count,
            total_result_count,
            reputation,
            community_votes,
            detections,
            categories,
            tags,
            names,
            meaningful_name,
            file_type,
            country,
            asn,
            as_owner,
            last_analysis_date,
            permalink,
            last_checked
        )
        VALUES (
            :indicator,
            :indicator_type,
            :report_available,
            :resource_type,
            :resource_id,
            :malicious_count,
            :suspicious_count,
            :harmless_count,
            :undetected_count,
            :timeout_count,
            :failure_count,
            :type_unsupported_count,
            :confirmed_timeout_count,
            :total_engine_count,
            :total_result_count,
            :reputation,
            CAST(:community_votes AS JSONB),
            CAST(:detections AS JSONB),
            CAST(:categories AS JSONB),
            CAST(:tags AS JSONB),
            CAST(:names AS JSONB),
            :meaningful_name,
            :file_type,
            :country,
            :asn,
            :as_owner,
            :last_analysis_date,
            :permalink,
            CURRENT_TIMESTAMP
        )
        ON CONFLICT (indicator, indicator_type)
        DO UPDATE SET
            report_available = EXCLUDED.report_available,
            resource_type = EXCLUDED.resource_type,
            resource_id = EXCLUDED.resource_id,
            malicious_count = EXCLUDED.malicious_count,
            suspicious_count = EXCLUDED.suspicious_count,
            harmless_count = EXCLUDED.harmless_count,
            undetected_count = EXCLUDED.undetected_count,
            timeout_count = EXCLUDED.timeout_count,
            failure_count = EXCLUDED.failure_count,
            type_unsupported_count = (
                EXCLUDED.type_unsupported_count
            ),
            confirmed_timeout_count = (
                EXCLUDED.confirmed_timeout_count
            ),
            total_engine_count = EXCLUDED.total_engine_count,
            total_result_count = EXCLUDED.total_result_count,
            reputation = EXCLUDED.reputation,
            community_votes = EXCLUDED.community_votes,
            detections = EXCLUDED.detections,
            categories = EXCLUDED.categories,
            tags = EXCLUDED.tags,
            names = EXCLUDED.names,
            meaningful_name = EXCLUDED.meaningful_name,
            file_type = EXCLUDED.file_type,
            country = EXCLUDED.country,
            asn = EXCLUDED.asn,
            as_owner = EXCLUDED.as_owner,
            last_analysis_date = EXCLUDED.last_analysis_date,
            permalink = EXCLUDED.permalink,
            last_checked = CURRENT_TIMESTAMP;
        """
    )

    parameters = {
        "indicator": indicator_data["indicator"],
        "indicator_type": (
            indicator_data["indicator_type"]
        ),
        "report_available": indicator_data.get(
            "report_available",
            True,
        ),
        "resource_type": indicator_data.get(
            "resource_type"
        ),
        "resource_id": indicator_data.get(
            "resource_id"
        ),
        "reputation": indicator_data.get(
            "reputation"
        ),
        "meaningful_name": indicator_data.get(
            "meaningful_name"
        ),
        "file_type": indicator_data.get(
            "file_type"
        ),
        "country": indicator_data.get("country"),
        "asn": indicator_data.get("asn"),
        "as_owner": indicator_data.get(
            "as_owner"
        ),
        "last_analysis_date": indicator_data.get(
            "last_analysis_date"
        ),
        "permalink": indicator_data.get(
            "permalink"
        ),
    }

    for field_name in VIRUSTOTAL_COUNT_FIELDS:
        parameters[field_name] = (
            indicator_data.get(field_name, 0)
        )

    for field_name in VIRUSTOTAL_JSON_FIELDS:
        default_value = (
            {}
            if field_name == "community_votes"
            else []
        )
        parameters[field_name] = json.dumps(
            indicator_data.get(
                field_name,
                default_value,
            )
        )

    with engine.begin() as connection:
        connection.execute(
            query,
            parameters,
        )


def get_virustotal_indicator_details(
    indicator,
    indicator_type,
):
    query = text(
        """
        SELECT
            indicator,
            indicator_type,
            report_available,
            resource_type,
            resource_id,
            malicious_count,
            suspicious_count,
            harmless_count,
            undetected_count,
            timeout_count,
            failure_count,
            type_unsupported_count,
            confirmed_timeout_count,
            total_engine_count,
            total_result_count,
            reputation,
            community_votes,
            detections,
            categories,
            tags,
            names,
            meaningful_name,
            file_type,
            country,
            asn,
            as_owner,
            last_analysis_date,
            permalink,
            last_checked
        FROM virustotal_indicators
        WHERE
            indicator = :indicator
            AND indicator_type = :indicator_type;
        """
    )

    with engine.connect() as connection:
        result = connection.execute(
            query,
            {
                "indicator": indicator,
                "indicator_type": indicator_type,
            },
        )
        row = result.fetchone()

    if row is None:
        return None

    return dict(row._mapping)


def get_virustotal_last_checked(
    indicator,
    indicator_type,
):
    query = text(
        """
        SELECT last_checked
        FROM virustotal_indicators
        WHERE
            indicator = :indicator
            AND indicator_type = :indicator_type;
        """
    )

    with engine.connect() as connection:
        result = connection.execute(
            query,
            {
                "indicator": indicator,
                "indicator_type": indicator_type,
            },
        )
        row = result.fetchone()

    if row is None:
        return None

    return row.last_checked