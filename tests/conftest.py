import os
import pytest
from pathlib import Path
from sqlalchemy import text
from dotenv import load_dotenv
from sqlalchemy.engine import make_url


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INTEGRATION_FLAG = "RUN_POSTGRES_INTEGRATION"
TEST_DATABASE_NAME = "threat_intel_test_db"


def _configure_integration_database():
    if os.getenv(INTEGRATION_FLAG) != "1":
        return

    load_dotenv(PROJECT_ROOT / ".env", override=False)

    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is required for PostgreSQL integration tests.")

    source_url = make_url(database_url)
    test_url = source_url.set(database=TEST_DATABASE_NAME)

    if test_url.database == source_url.database:
        raise RuntimeError("The integration database must differ from the normal database.")

    if test_url.database != TEST_DATABASE_NAME:
        raise RuntimeError("Unsafe integration database target.")

    os.environ["DATABASE_URL"] = test_url.render_as_string(hide_password=False)

def _reset_integration_database(engine):
    with engine.begin() as connection:
        database_name = connection.execute(
            text("SELECT current_database()")
        ).scalar_one()

        if database_name != TEST_DATABASE_NAME:
            raise RuntimeError(
                f"Refusing to clean unsafe database: {database_name}"
            )

        connection.execute(
            text(
                """
                TRUNCATE TABLE
                    public.article_analysis,
                    public.article_iocs,
                    public.articles,
                    public.cve_enrichment,
                    public.github_advisories,
                    public.github_advisory_vulnerabilities,
                    public.intelligence_embeddings,
                    public.mitre_techniques,
                    public.otx_indicators,
                    public.virustotal_indicators
                RESTART IDENTITY CASCADE
                """
            )
        )

@pytest.fixture(autouse=True)
def isolate_integration_database(request):
    if request.node.get_closest_marker("integration") is None:
        yield
        return

    if os.getenv(INTEGRATION_FLAG) != "1":
        pytest.skip(
            "Set RUN_POSTGRES_INTEGRATION=1 to run PostgreSQL integration tests."
        )

    from database.connection import engine

    _reset_integration_database(engine)

    try:
        yield
    finally:
        _reset_integration_database(engine)

_configure_integration_database()