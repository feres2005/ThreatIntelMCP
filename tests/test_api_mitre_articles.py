from fastapi.testclient import TestClient

from api.app import app
from api.routers import mitre as mitre_router


def test_mitre_article_evidence_delegates_to_repository(
    monkeypatch,
):
    calls = []

    def fake_get_supporting_articles(
        technique_id,
        limit=20,
    ):
        calls.append(
            (technique_id, limit)
        )

        return {
            "technique_id": "T1530",
            "supporting_article_count": 2,
            "articles": [
                {
                    "article_id": 13316,
                    "title": (
                        "Cloud data campaign"
                    ),
                    "link": (
                        "https://example.com/"
                        "article-13316"
                    ),
                    "source": "the_hacker_news",
                    "published": (
                        "2026-08-20T12:00:00Z"
                    ),
                    "severity": "High",
                    "confidence_score": 0.75,
                }
            ],
        }

    monkeypatch.setattr(
        mitre_router,
        "get_mitre_supporting_articles",
        fake_get_supporting_articles,
    )

    with TestClient(app) as client:
        response = client.get(
            (
                "/api/v1/mitre/"
                "techniques/t1530/articles"
            ),
            params={
                "limit": 5,
            },
        )

    assert response.status_code == 200
    assert calls == [
        ("t1530", 5)
    ]

    assert response.json() == {
        "technique_id": "T1530",
        "limit": 5,
        "supporting_article_count": 2,
        "returned_count": 1,
        "articles": [
            {
                "article_id": 13316,
                "title": "Cloud data campaign",
                "link": (
                    "https://example.com/"
                    "article-13316"
                ),
                "source": "the_hacker_news",
                "published": (
                    "2026-08-20T12:00:00Z"
                ),
                "severity": "High",
                "confidence_score": 0.75,
            }
        ],
    }


def test_mitre_article_evidence_returns_empty_result(
    monkeypatch,
):
    def fake_get_supporting_articles(
        technique_id,
        limit=20,
    ):
        return {
            "technique_id": "T9999",
            "supporting_article_count": 0,
            "articles": [],
        }

    monkeypatch.setattr(
        mitre_router,
        "get_mitre_supporting_articles",
        fake_get_supporting_articles,
    )

    with TestClient(app) as client:
        response = client.get(
            (
                "/api/v1/mitre/"
                "techniques/T9999/articles"
            )
        )

    assert response.status_code == 200
    assert response.json() == {
        "technique_id": "T9999",
        "limit": 20,
        "supporting_article_count": 0,
        "returned_count": 0,
        "articles": [],
    }


def test_mitre_article_evidence_maps_validation_error(
    monkeypatch,
):
    def fake_get_supporting_articles(
        technique_id,
        limit=20,
    ):
        raise ValueError(
            "MITRE technique ID must follow "
            "the format TNNNN or TNNNN.NNN."
        )

    monkeypatch.setattr(
        mitre_router,
        "get_mitre_supporting_articles",
        fake_get_supporting_articles,
    )

    with TestClient(app) as client:
        response = client.get(
            (
                "/api/v1/mitre/"
                "techniques/invalid/articles"
            )
        )

    assert response.status_code == 422
    assert response.json() == {
        "detail": (
            "MITRE technique ID must follow "
            "the format TNNNN or TNNNN.NNN."
        )
    }


def test_mitre_article_evidence_rejects_invalid_limit(
    monkeypatch,
):
    repository_called = False

    def fake_get_supporting_articles(
        technique_id,
        limit=20,
    ):
        nonlocal repository_called
        repository_called = True
        return {
            "technique_id": "T1530",
            "supporting_article_count": 0,
            "articles": [],
        }

    monkeypatch.setattr(
        mitre_router,
        "get_mitre_supporting_articles",
        fake_get_supporting_articles,
    )

    with TestClient(app) as client:
        response = client.get(
            (
                "/api/v1/mitre/"
                "techniques/T1530/articles"
            ),
            params={
                "limit": 51,
            },
        )

    assert response.status_code == 422
    assert repository_called is False