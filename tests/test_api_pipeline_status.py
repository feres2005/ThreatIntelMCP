from fastapi.testclient import TestClient

from api.app import app
from api.routers import (
    pipeline_status as pipeline_status_router,
)


CONTROLLED_STATUS = {
    "operation": "get_pipeline_status",
    "health_status": "healthy",
    "work_pending": {
        "article_processing": 2,
        "embedding_indexing": 0,
    },
    "coverage": {
        "processing_percent": 80.0,
        "analysis_percent": 75.0,
        "embedding_percent": 100.0,
    },
    "counts": {
        "total_articles": 10,
        "processed_articles": 8,
        "pending_articles": 2,
        "analyzed_articles": 7,
        "processed_without_analysis": 1,
        "pending_with_analysis": 0,
        "typed_ioc_rows": 3,
        "articles_with_typed_iocs": 2,
        "article_embeddings": 10,
        "articles_missing_embeddings": 0,
        "enriched_cves": 4,
        "cached_otx_indicators": 5,
        "mitre_techniques": 100,
        "github_advisories": 200,
    },
    "warnings": [],
}


def test_pipeline_status_delegates_to_service(
    monkeypatch,
):
    service_calls = []

    def fake_get_pipeline_status():
        service_calls.append("called")
        return CONTROLLED_STATUS

    monkeypatch.setattr(
        pipeline_status_router,
        "get_pipeline_status_service",
        fake_get_pipeline_status,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/pipeline/status"
        )

    assert response.status_code == 200
    assert response.json() == CONTROLLED_STATUS
    assert service_calls == ["called"]