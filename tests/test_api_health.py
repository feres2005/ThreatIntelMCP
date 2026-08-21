from fastapi.testclient import TestClient

from api.app import app


def test_health_endpoint_returns_service_metadata():
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.headers[
        "content-type"
    ].startswith("application/json")
    assert response.json() == {
        "status": "healthy",
        "service": "ThreatIntelMCP REST API",
        "version": "1.0.0",
    }
