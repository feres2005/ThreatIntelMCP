from fastapi.testclient import TestClient

from api.app import app
from api.routers import (
    pipeline_status as pipeline_router,
)


def test_unexpected_error_returns_safe_json(
    monkeypatch,
):
    def failing_status_service():
        raise RuntimeError(
            "Sensitive internal test error."
        )

    monkeypatch.setattr(
        pipeline_router,
        "get_pipeline_status_service",
        failing_status_service,
    )

    with TestClient(
        app,
        raise_server_exceptions=False,
    ) as client:
        response = client.get(
            "/api/v1/pipeline/status"
        )

    assert response.status_code == 500
    assert response.json() == {
        "detail": "Internal server error."
    }

    assert (
        "Sensitive internal test error."
        not in response.text
    )