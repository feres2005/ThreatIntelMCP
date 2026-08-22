import pytest
from sqlalchemy import text

from database.connection import engine


pytestmark = pytest.mark.integration

EXPECTED_TABLES = {
    "article_analysis",
    "article_iocs",
    "articles",
    "cve_enrichment",
    "github_advisories",
    "github_advisory_vulnerabilities",
    "intelligence_embeddings",
    "mitre_techniques",
    "otx_indicators",
}


def test_postgresql_integration_database_boundary():
    with engine.connect() as connection:
        database_name = connection.execute(
            text("SELECT current_database()")
        ).scalar_one()

        table_names = set(
            connection.execute(
                text(
                    """
                    SELECT table_name
                    FROM information_schema.tables
                    WHERE table_schema = :schema
                      AND table_type = :kind
                    """
                ),
                {"schema": "public", "kind": "BASE TABLE"},
            ).scalars()
        )

        vector_enabled = connection.execute(
            text(
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_extension
                    WHERE extname = :extension
                )
                """
            ),
            {"extension": "vector"},
        ).scalar_one()

    assert database_name == "threat_intel_test_db"
    assert table_names == EXPECTED_TABLES
    assert vector_enabled is True
