from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from api.app import app
from api.routers import topics as topics_router


pytestmark = pytest.mark.contract


def test_emerging_topics_returns_service_result(
    monkeypatch,
):
    calls = []
    generated_at = datetime(
        2026,
        8,
        22,
        12,
        0,
        tzinfo=timezone.utc,
    )

    def fake_detect_emerging_topics(**kwargs):
        calls.append(kwargs)

        return {
            "generated_at": generated_at,
            "observation_days": 30,
            "recent_days": 7,
            "limit": 5,
            "considered_article_count": 0,
            "clustered_article_count": 0,
            "noise_article_count": 0,
            "topics": [],
        }

    monkeypatch.setattr(
        topics_router,
        "detect_emerging_topics",
        fake_detect_emerging_topics,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/topics/emerging",
            params={
                "observation_days": 30,
                "recent_days": 7,
                "limit": 5,
            },
        )

    assert response.status_code == 200
    assert calls == [
        {
            "observation_days": 30,
            "recent_days": 7,
            "limit": 5,
        },
    ]

    assert response.json() == {
        "generated_at": (
            "2026-08-22T12:00:00Z"
        ),
        "observation_days": 30,
        "recent_days": 7,
        "limit": 5,
        "considered_article_count": 0,
        "clustered_article_count": 0,
        "noise_article_count": 0,
        "topics": [],
    }

def test_emerging_topics_returns_structured_evidence(
    monkeypatch,
):
    generated_at = datetime(
        2026,
        8,
        22,
        12,
        0,
        tzinfo=timezone.utc,
    )

    def fake_detect_emerging_topics(**kwargs):
        return {
            "generated_at": generated_at,
            "observation_days": 30,
            "recent_days": 7,
            "limit": 10,
            "considered_article_count": 4,
            "clustered_article_count": 3,
            "noise_article_count": 1,
            "topics": [
                {
                    "label": "Clop ransomware",
                    "keywords": [
                        "clop",
                        "ransomware",
                        "flexplm",
                    ],
                    "article_count": 3,
                    "recent_article_count": 2,
                    "previous_article_count": 1,
                    "recent_share": 0.5,
                    "previous_share": 0.25,
                    "trend": "rising",
                    "trend_score": 0.5,
                    "sources": [
                        "feed_a",
                        "feed_b",
                    ],
                    "classifications": [
                        "ransomware",
                    ],
                    "severities": ["High"],
                    "cves": ["CVE-2026-12345"],
                    "malware": ["Clop"],
                    "mitre_techniques": ["T1486"],
                    "apt_groups": [],
                    "targeted_sectors": [
                        "Manufacturing",
                    ],
                    "affected_technologies": [
                        "FlexPLM",
                    ],
                    "representative_articles": [
                        {
                            "article_id": 1201,
                            "title": (
                                "Clop targets FlexPLM"
                            ),
                            "link": (
                                "https://example.com/"
                                "articles/1201"
                            ),
                            "source": "feed_a",
                            "published": generated_at,
                            "similarity_to_centroid": (
                                0.97
                            ),
                        },
                    ],
                },
            ],
        }

    monkeypatch.setattr(
        topics_router,
        "detect_emerging_topics",
        fake_detect_emerging_topics,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/topics/emerging"
        )

    assert response.status_code == 200

    payload = response.json()
    topic = payload["topics"][0]

    assert topic["label"] == "Clop ransomware"
    assert topic["trend"] == "rising"
    assert topic["trend_score"] == 0.5
    assert topic["cves"] == ["CVE-2026-12345"]
    assert topic["mitre_techniques"] == ["T1486"]
    assert topic["representative_articles"][0][
        "article_id"
    ] == 1201

@pytest.mark.parametrize(
    "parameters",
    [
        {"observation_days": 1},
        {"observation_days": 91},
        {"recent_days": 0},
        {"recent_days": 31},
        {"limit": 0},
        {"limit": 21},
        {
            "observation_days": 7,
            "recent_days": 7,
        },
    ],
)
def test_emerging_topics_rejects_invalid_parameters(
    monkeypatch,
    parameters,
):
    service_called = False

    def fake_detect_emerging_topics(**kwargs):
        nonlocal service_called
        service_called = True
        return {}

    monkeypatch.setattr(
        topics_router,
        "detect_emerging_topics",
        fake_detect_emerging_topics,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/topics/emerging",
            params=parameters,
        )

    assert response.status_code == 422
    assert service_called is False


def test_emerging_topics_maps_service_failure(
    monkeypatch,
):
    def failing_detect_emerging_topics(**kwargs):
        raise RuntimeError(
            "Controlled topic failure."
        )

    monkeypatch.setattr(
        topics_router,
        "detect_emerging_topics",
        failing_detect_emerging_topics,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/topics/emerging"
        )

    assert response.status_code == 503
    assert response.json() == {
        "detail": (
            "Emerging topic detection is "
            "temporarily unavailable."
        ),
    }
