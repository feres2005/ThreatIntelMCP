import pytest
from fastapi.testclient import TestClient

from api.app import app
from api.routers import articles as articles_router


CONTROLLED_ARTICLE = {
    "article_id": 565,
    "title": "Controlled threat article",
    "link": "https://example.com/threat-article",
    "published": None,
    "summary": "Controlled article summary.",
    "classification": ["malware"],
    "severity": "High",
    "confidence_score": 0.9,
    "iocs": ["192.0.2.10"],
    "cves": [],
    "malware": ["ControlledMalware"],
    "mitre_techniques": ["T1105"],
    "apt_groups": [],
    "targeted_sectors": ["Technology"],
    "affected_technologies": ["Windows"],
}
CONTROLLED_SEARCH_RESULTS = [
    {
        "article_id": 13263,
        "title": "Controlled malware article",
        "summary": "Controlled search summary.",
        "severity": "High",
        "confidence_score": 0.92,
        "cves": [],
        "malware": ["ControlledMalware"],
        "mitre_techniques": ["T1105"],
    },
]

def test_get_existing_article_returns_details(
    monkeypatch,
):
    requested_ids = []

    def fake_get_article_details(article_id):
        requested_ids.append(article_id)
        return CONTROLLED_ARTICLE

    monkeypatch.setattr(
        articles_router,
        "get_article_details_repository",
        fake_get_article_details,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/articles/565"
        )

    assert response.status_code == 200
    assert response.json() == CONTROLLED_ARTICLE
    assert requested_ids == [565]


def test_get_missing_article_returns_404(
    monkeypatch,
):
    requested_ids = []

    def fake_get_article_details(article_id):
        requested_ids.append(article_id)
        return None

    monkeypatch.setattr(
        articles_router,
        "get_article_details_repository",
        fake_get_article_details,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/articles/999999"
        )

    assert response.status_code == 404
    assert response.json() == {
        "detail": (
            "Analyzed article 999999 "
            "was not found."
        ),
    }
    assert requested_ids == [999999]


@pytest.mark.parametrize(
    "invalid_article_id",
    [
        "0",
        "-1",
        "not-an-integer",
    ],
)
def test_invalid_article_id_returns_422(
    monkeypatch,
    invalid_article_id,
):
    def unexpected_repository_call(article_id):
        raise AssertionError(
            "Repository must not be called "
            "for an invalid article ID."
        )

    monkeypatch.setattr(
        articles_router,
        "get_article_details_repository",
        unexpected_repository_call,
    )

    with TestClient(app) as client:
        response = client.get(
            f"/api/v1/articles/"
            f"{invalid_article_id}"
        )

    assert response.status_code == 422

def test_search_articles_returns_paginated_results(
    monkeypatch,
):
    repository_calls = []

    def fake_search_articles(
        keyword,
        limit=10,
        offset=0,
    ):
        repository_calls.append({
            "keyword": keyword,
            "limit": limit,
            "offset": offset,
        })
        return CONTROLLED_SEARCH_RESULTS

    monkeypatch.setattr(
        articles_router,
        "search_articles_repository",
        fake_search_articles,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/articles",
            params={
                "keyword": "  malware  ",
                "limit": 2,
                "offset": 4,
            },
        )

    assert response.status_code == 200
    assert response.json() == {
        "keyword": "malware",
        "limit": 2,
        "offset": 4,
        "returned_count": 1,
        "results": CONTROLLED_SEARCH_RESULTS,
    }
    assert repository_calls == [
        {
            "keyword": "malware",
            "limit": 2,
            "offset": 4,
        }
    ]


@pytest.mark.parametrize(
    "query_parameters",
    [
        {},
        {"keyword": "   "},
        {
            "keyword": "malware",
            "limit": 0,
        },
        {
            "keyword": "malware",
            "limit": 51,
        },
        {
            "keyword": "malware",
            "offset": -1,
        },
    ],
)
def test_invalid_article_search_returns_422(
    monkeypatch,
    query_parameters,
):
    def unexpected_repository_call(
        keyword,
        limit=10,
        offset=0,
    ):
        raise AssertionError(
            "Repository must not be called "
            "for invalid search parameters."
        )

    monkeypatch.setattr(
        articles_router,
        "search_articles_repository",
        unexpected_repository_call,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/articles",
            params=query_parameters,
        )

    assert response.status_code == 422