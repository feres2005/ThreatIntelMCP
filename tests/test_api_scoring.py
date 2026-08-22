import pytest
from fastapi.testclient import TestClient

from api.app import app
from api.routers import articles as articles_router


CONTROLLED_SCORING_REPORT = {
    "target": {
        "entity_type": "article",
        "article_id": 4836,
        "title": "Controlled vulnerability article",
    },
    "otx_selection": None,
    "scoring_version": "1.0",
    "threat": {
        "scoring_version": "1.0",
        "threat_score": 54.4,
        "threat_level": "High",
        "evidence_present": True,
        "components": {
            "article_severity": {
                "points": 30,
            },
            "cvss": {
                "points": 23.4,
            },
        },
        "warnings": [],
    },
    "confidence": {
        "scoring_version": "1.0",
        "confidence_score": 53.75,
        "confidence_level": "High",
        "components": {
            "supporting_articles": {
                "points": 15,
            },
            "ai_confidence": {
                "points": 23.75,
            },
        },
        "warnings": [],
    },
    "priority": {
        "threat_level": "High",
        "confidence_level": "High",
        "priority_code": "P1",
        "priority_label": "Urgent",
        "recommended_action": (
            "Urgent investigation"
        ),
    },
    "warnings": [],
}


def test_article_scoring_defaults_otx_disabled(
    monkeypatch,
):
    service_calls = []

    def fake_score_article(
        article_id,
        include_otx=True,
    ):
        service_calls.append({
            "article_id": article_id,
            "include_otx": include_otx,
        })
        return CONTROLLED_SCORING_REPORT

    monkeypatch.setattr(
        articles_router,
        "score_article_service",
        fake_score_article,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/articles/4836/score"
        )

    assert response.status_code == 200
    assert response.json() == (
        CONTROLLED_SCORING_REPORT
    )
    assert service_calls == [
        {
            "article_id": 4836,
            "include_otx": False,
        }
    ]


def test_article_scoring_allows_otx_opt_in(
    monkeypatch,
):
    service_calls = []

    def fake_score_article(
        article_id,
        include_otx=True,
    ):
        service_calls.append({
            "article_id": article_id,
            "include_otx": include_otx,
        })
        return CONTROLLED_SCORING_REPORT

    monkeypatch.setattr(
        articles_router,
        "score_article_service",
        fake_score_article,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/articles/4836/score",
            params={
                "include_otx": "true",
            },
        )

    assert response.status_code == 200
    assert service_calls == [
        {
            "article_id": 4836,
            "include_otx": True,
        }
    ]


def test_missing_article_score_returns_404(
    monkeypatch,
):
    monkeypatch.setattr(
        articles_router,
        "score_article_service",
        lambda article_id, include_otx: None,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/articles/999999999/score"
        )

    assert response.status_code == 404
    assert response.json() == {
        "detail": (
            "Scoring report for analyzed "
            "article 999999999 was not found."
        ),
    }


@pytest.mark.parametrize(
    ("path", "parameters"),
    [
        (
            "/api/v1/articles/0/score",
            {},
        ),
        (
            "/api/v1/articles/4836/score",
            {"include_otx": "invalid"},
        ),
    ],
)
def test_invalid_article_score_returns_422(
    monkeypatch,
    path,
    parameters,
):
    def unexpected_service_call(
        article_id,
        include_otx,
    ):
        raise AssertionError(
            "Scoring service must not run "
            "for invalid parameters."
        )

    monkeypatch.setattr(
        articles_router,
        "score_article_service",
        unexpected_service_call,
    )

    with TestClient(app) as client:
        response = client.get(
            path,
            params=parameters,
        )

    assert response.status_code == 422

@pytest.mark.contract
def test_article_scoring_returns_structured_warnings(
    monkeypatch,
):
    structured_warning = {
        "source": "threat",
        "message": (
            "Unsupported article severity was "
            "treated as unknown."
        ),
    }

    warning_report = {
        **CONTROLLED_SCORING_REPORT,
        "warnings": [structured_warning],
    }

    monkeypatch.setattr(
        articles_router,
        "score_article_service",
        lambda article_id, include_otx: warning_report,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/articles/4836/score"
        )

    assert response.status_code == 200
    assert response.json()["warnings"] == [
        structured_warning
    ]