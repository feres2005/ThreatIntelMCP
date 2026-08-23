from fastapi.testclient import TestClient

from api.app import app
from api.routers import search as search_router


def test_semantic_search_delegates_to_worker(
    monkeypatch,
):
    calls = []

    async def fake_search_worker(
        search_query,
        limit,
    ):
        calls.append((search_query, limit))

        return [
            {
                "article_id": 13250,
                "title": "Gunra Ransomware",
                "link": (
                    "https://example.com/"
                    "gunra-ransomware"
                ),
                "source": "test_source",
                "published": (
                    "2026-08-11T11:16:24+02:00"
                ),
                "summary": (
                    "A ransomware campaign "
                    "targeting organizations."
                ),
                "analysis_available": False,
                "similarity": 0.86,
            }
        ]

    monkeypatch.setattr(
        search_router,
        "run_semantic_search_worker",
        fake_search_worker,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/search/articles/semantic",
            params={
                "search_query": (
                    "  ransomware campaign  "
                ),
                "limit": 2,
            },
        )

    assert response.status_code == 200
    assert calls == [
        ("ransomware campaign", 2)
    ]

    payload = response.json()

    assert payload["search_query"] == (
        "ransomware campaign"
    )
    assert payload["limit"] == 2
    assert payload["returned_count"] == 1
    assert payload["results"][0][
        "article_id"
    ] == 13250
    assert payload["results"][0][
        "analysis_available"
    ] is False


def test_semantic_search_rejects_invalid_input(
    monkeypatch,
):
    worker_called = False

    async def fake_search_worker(
        search_query,
        limit,
    ):
        nonlocal worker_called
        worker_called = True
        return []

    monkeypatch.setattr(
        search_router,
        "run_semantic_search_worker",
        fake_search_worker,
    )

    invalid_requests = [
        {
            "search_query": "   ",
            "limit": 10,
        },
        {
            "search_query": "malware",
            "limit": 0,
        },
        {
            "search_query": "malware",
            "limit": 51,
        },
        {
            "search_query": "x" * 501,
            "limit": 10,
        },
    ]

    with TestClient(app) as client:
        for parameters in invalid_requests:
            response = client.get(
                (
                    "/api/v1/search/"
                    "articles/semantic"
                ),
                params=parameters,
            )

            assert response.status_code == 422

    assert worker_called is False


def test_semantic_search_maps_worker_failure(
    monkeypatch,
):
    async def failing_search_worker(
        search_query,
        limit,
    ):
        raise RuntimeError(
            "Simulated semantic worker failure."
        )

    monkeypatch.setattr(
        search_router,
        "run_semantic_search_worker",
        failing_search_worker,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/search/articles/semantic",
            params={
                "search_query": "ransomware",
                "limit": 3,
            },
        )

    assert response.status_code == 503
    assert response.json() == {
        "detail": (
            "Semantic search is temporarily "
            "unavailable."
        )
    }
