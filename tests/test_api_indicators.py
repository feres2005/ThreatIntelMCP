import pytest
from fastapi.testclient import TestClient

from api.app import app
from api.routers import (
    indicators as indicators_router,
)


CONTROLLED_CORRELATION = {
    "indicator": "8.8.8.8",
    "indicator_type": "IPv4",
    "supporting_article_count": 0,
    "supporting_article_ids": [],
    "supporting_articles": [],
    "related_entities": {
        "cves": [],
        "malware": [],
        "mitre_techniques": [],
        "apt_groups": [],
        "targeted_sectors": [],
        "affected_technologies": [],
    },
    "otx_enrichment": None,
}

CONTROLLED_INDICATOR_SCORE = {
    "target": {
        "entity_type": "indicator",
        "indicator": "8.8.8.8",
        "indicator_type": "IPv4",
    },
    "scoring_version": "1.0",
    "threat": {
        "scoring_version": "1.0",
        "threat_score": 0.0,
        "threat_level": "Unknown",
        "evidence_present": False,
        "components": {
            "otx": {
                "points": 0,
            },
        },
        "warnings": [],
    },
    "confidence": {
        "scoring_version": "1.0",
        "confidence_score": 0.0,
        "confidence_level": "Low",
        "components": {
            "otx_corroboration": {
                "points": 0,
            },
        },
        "warnings": [],
    },
    "priority": {
        "threat_level": "Unknown",
        "confidence_level": "Low",
        "priority_code": "P4",
        "priority_label": "Low",
        "recommended_action": (
            "Gather intelligence"
        ),
    },
    "warnings": [],
}


def test_indicator_correlation_defaults_otx_disabled(
    monkeypatch,
):
    service_calls = []

    def fake_correlate(
        indicator,
        include_otx=True,
    ):
        service_calls.append({
            "indicator": indicator,
            "include_otx": include_otx,
        })
        return CONTROLLED_CORRELATION

    monkeypatch.setattr(
        indicators_router,
        "correlate_indicator_service",
        fake_correlate,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/indicators/correlation",
            params={
                "indicator": "  8.8.8.8  ",
            },
        )

    assert response.status_code == 200
    assert response.json() == CONTROLLED_CORRELATION
    assert service_calls == [
        {
            "indicator": "8.8.8.8",
            "include_otx": False,
        }
    ]


def test_indicator_scoring_allows_otx_opt_in(
    monkeypatch,
):
    service_calls = []

    def fake_score(
        indicator,
        include_otx=True,
    ):
        service_calls.append({
            "indicator": indicator,
            "include_otx": include_otx,
        })
        return CONTROLLED_INDICATOR_SCORE

    monkeypatch.setattr(
        indicators_router,
        "score_indicator_service",
        fake_score,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/indicators/score",
            params={
                "indicator": "8.8.8.8",
                "include_otx": "true",
            },
        )

    assert response.status_code == 200
    assert response.json() == (
        CONTROLLED_INDICATOR_SCORE
    )
    assert service_calls == [
        {
            "indicator": "8.8.8.8",
            "include_otx": True,
        }
    ]


@pytest.mark.parametrize(
    ("path", "service_attribute"),
    [
        (
            "/api/v1/indicators/correlation",
            "correlate_indicator_service",
        ),
        (
            "/api/v1/indicators/score",
            "score_indicator_service",
        ),
    ],
)
def test_invalid_ioc_service_error_becomes_422(
    monkeypatch,
    path,
    service_attribute,
):
    def fake_invalid_indicator(
        indicator,
        include_otx,
    ):
        raise ValueError(
            "A valid supported IOC is required."
        )

    monkeypatch.setattr(
        indicators_router,
        service_attribute,
        fake_invalid_indicator,
    )

    with TestClient(app) as client:
        response = client.get(
            path,
            params={
                "indicator": "not-an-ioc",
            },
        )

    assert response.status_code == 422
    assert response.json() == {
        "detail": (
            "A valid supported IOC is required."
        ),
    }


@pytest.mark.parametrize(
    ("path", "parameters"),
    [
        (
            "/api/v1/indicators/correlation",
            {"indicator": "   "},
        ),
        (
            "/api/v1/indicators/score",
            {
                "indicator": "8.8.8.8",
                "include_otx": "invalid",
            },
        ),
    ],
)
def test_invalid_indicator_http_input_returns_422(
    monkeypatch,
    path,
    parameters,
):
    def unexpected_service_call(
        indicator,
        include_otx,
    ):
        raise AssertionError(
            "Indicator service must not run "
            "for invalid HTTP input."
        )

    monkeypatch.setattr(
        indicators_router,
        "correlate_indicator_service",
        unexpected_service_call,
    )
    monkeypatch.setattr(
        indicators_router,
        "score_indicator_service",
        unexpected_service_call,
    )

    with TestClient(app) as client:
        response = client.get(
            path,
            params=parameters,
        )

    assert response.status_code == 422