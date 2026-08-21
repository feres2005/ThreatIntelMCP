import pytest
from fastapi.testclient import TestClient

from api.app import app
from api.routers import articles as articles_router


CONTROLLED_INVESTIGATION = {
    "article": {
        "article_id": 4836,
        "title": "Controlled vulnerability article",
        "link": "https://example.com/article-4836",
        "published": None,
        "summary": "Controlled investigation.",
        "classification": ["vulnerability"],
        "severity": "Critical",
        "confidence_score": 0.95,
        "iocs": [],
        "cves": ["CVE-2026-46242"],
        "malware": [],
        "mitre_techniques": ["T1548.004"],
        "apt_groups": [],
        "targeted_sectors": [],
        "affected_technologies": ["Linux"],
    },
    "typed_iocs": [],
    "ioc_enrichment": [],
    "cve_enrichment": [
        {
            "cve_id": "CVE-2026-46242",
            "enrichment_available": True,
            "details": {
                "cvss_score": 7.8,
                "severity": "HIGH",
            },
        },
    ],
    "mitre_enrichment": [
        {
            "technique_id": "T1548.004",
            "enrichment_available": True,
            "details": {
                "name": (
                    "Elevated Execution with Prompt"
                ),
            },
        },
    ],
}


def test_investigation_defaults_otx_disabled(
    monkeypatch,
):
    service_calls = []

    def fake_investigation(
        article_id,
        include_otx=True,
    ):
        service_calls.append({
            "article_id": article_id,
            "include_otx": include_otx,
        })
        return CONTROLLED_INVESTIGATION

    monkeypatch.setattr(
        articles_router,
        "get_article_investigation_service",
        fake_investigation,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/articles/4836/investigation"
        )

    assert response.status_code == 200
    assert response.json() == CONTROLLED_INVESTIGATION
    assert service_calls == [
        {
            "article_id": 4836,
            "include_otx": False,
        }
    ]


def test_investigation_allows_otx_opt_in(
    monkeypatch,
):
    service_calls = []

    def fake_investigation(
        article_id,
        include_otx=True,
    ):
        service_calls.append({
            "article_id": article_id,
            "include_otx": include_otx,
        })
        return CONTROLLED_INVESTIGATION

    monkeypatch.setattr(
        articles_router,
        "get_article_investigation_service",
        fake_investigation,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/articles/4836/investigation",
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


def test_missing_investigation_returns_404(
    monkeypatch,
):
    monkeypatch.setattr(
        articles_router,
        "get_article_investigation_service",
        lambda article_id, include_otx: None,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/articles/999999999/"
            "investigation"
        )

    assert response.status_code == 404
    assert response.json() == {
        "detail": (
            "Investigation for analyzed "
            "article 999999999 was not found."
        ),
    }


@pytest.mark.parametrize(
    ("path", "parameters"),
    [
        (
            "/api/v1/articles/0/investigation",
            {},
        ),
        (
            "/api/v1/articles/4836/investigation",
            {"include_otx": "not-a-boolean"},
        ),
    ],
)
def test_invalid_investigation_request_returns_422(
    monkeypatch,
    path,
    parameters,
):
    def unexpected_service_call(
        article_id,
        include_otx,
    ):
        raise AssertionError(
            "Investigation service must not run "
            "for invalid parameters."
        )

    monkeypatch.setattr(
        articles_router,
        "get_article_investigation_service",
        unexpected_service_call,
    )

    with TestClient(app) as client:
        response = client.get(
            path,
            params=parameters,
        )

    assert response.status_code == 422