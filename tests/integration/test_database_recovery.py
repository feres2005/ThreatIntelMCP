import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

from database.article_repository import count_articles
from database.connection import engine


pytestmark = pytest.mark.integration


def test_pool_recovers_from_terminated_connection():
    engine.dispose()

    with engine.connect() as connection:
        backend_pid = connection.execute(
            text("SELECT pg_backend_pid()")
        ).scalar_one()

    terminator_engine = create_engine(
        engine.url,
        poolclass=NullPool,
    )

    try:
        with terminator_engine.begin() as connection:
            terminated = connection.execute(
                text(
                    """
                    SELECT pg_terminate_backend(
                        :backend_pid
                    )
                    """
                ),
                {"backend_pid": backend_pid},
            ).scalar_one()
    finally:
        terminator_engine.dispose()

    assert terminated is True

    assert count_articles() == 0
