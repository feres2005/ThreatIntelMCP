from fastapi.testclient import TestClient

from api.app import app
from api.routers import (
    threat_entities as entity_router,
)


def test_entity_search_delegates_to_repository(
    monkeypatch,
):
    calls = []

    def fake_search(
        entity_type,
        keyword,
        limit=10,
        offset=0,
    ):
        calls.append(
            (
                entity_type,
                keyword,
                limit,
                offset,
            )
        )

        return {
            "entity_type": "malware",
            "keyword": "ransom",
            "limit": 5,
            "offset": 2,
            "returned_count": 1,
            "results": [
                {
                    "value": "Qilin",
                    "supporting_article_count": 2,
                    "latest_seen": (
                        "2026-08-20T12:30:00Z"
                    ),
                }
            ],
        }

    monkeypatch.setattr(
        entity_router,
        "search_threat_entity_values",
        fake_search,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/entities",
            params={
                "entity_type": "malware",
                "keyword": "  ransom  ",
                "limit": 5,
                "offset": 2,
            },
        )

    assert response.status_code == 200
    assert calls == [
        (
            "malware",
            "ransom",
            5,
            2,
        )
    ]

    payload = response.json()

    assert payload["returned_count"] == 1
    assert payload["results"][0] == {
        "value": "Qilin",
        "supporting_article_count": 2,
        "latest_seen": (
            "2026-08-20T12:30:00Z"
    ),
    }


def test_entity_evidence_delegates_to_repository(
    monkeypatch,
):
    calls = []

    def fake_evidence(
        entity_type,
        value,
        limit=20,
    ):
        calls.append(
            (
                entity_type,
                value,
                limit,
            )
        )

        return {
            "entity_type": "apt_group",
            "value": "Example Group",
            "limit": 12,
            "supporting_article_count": 1,
            "returned_count": 1,
            "articles": [
                {
                    "article_id": 13316,
                    "title": "Portal attack",
                    "link": (
                        "https://example.com/article"
                    ),
                    "source": "example_source",
                    "published": None,
                    "summary": "A threat campaign.",
                    "severity": "High",
                    "confidence_score": 0.85,
                    "cves": [
                        "CVE-2026-50522"
                    ],
                    "malware": ["ExampleRAT"],
                    "mitre_techniques": [
                        "T1530"
                    ],
                    "apt_groups": [
                        "Example Group"
                    ],
                    "targeted_sectors": [
                        "Government"
                    ],
                    "affected_technologies": [
                        "Microsoft 365"
                    ],
                }
            ],
        }

    monkeypatch.setattr(
        entity_router,
        "get_threat_entity_evidence",
        fake_evidence,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/entities/evidence",
            params={
                "entity_type": "apt_group",
                "value": "  Example Group  ",
                "limit": 12,
            },
        )

    assert response.status_code == 200
    assert calls == [
        (
            "apt_group",
            "Example Group",
            12,
        )
    ]
    assert response.json()[
        "supporting_article_count"
    ] == 1


def test_entity_endpoints_reject_invalid_inputs(
    monkeypatch,
):
    search_called = False
    evidence_called = False

    def fake_search(*args, **kwargs):
        nonlocal search_called
        search_called = True
        return {}

    def fake_evidence(*args, **kwargs):
        nonlocal evidence_called
        evidence_called = True
        return {}

    monkeypatch.setattr(
        entity_router,
        "search_threat_entity_values",
        fake_search,
    )
    monkeypatch.setattr(
        entity_router,
        "get_threat_entity_evidence",
        fake_evidence,
    )

    invalid_searches = [
        {
            "entity_type": "unknown",
            "keyword": "test",
        },
        {
            "entity_type": "malware",
            "keyword": "   ",
        },
        {
            "entity_type": "malware",
            "keyword": "test",
            "limit": 0,
        },
        {
            "entity_type": "malware",
            "keyword": "test",
            "offset": -1,
        },
    ]

    with TestClient(app) as client:
        for parameters in invalid_searches:
            response = client.get(
                "/api/v1/entities",
                params=parameters,
            )

            assert response.status_code == 422

        invalid_evidence = client.get(
            "/api/v1/entities/evidence",
            params={
                "entity_type": "apt_group",
                "value": "   ",
            },
        )

    assert invalid_evidence.status_code == 422
    assert search_called is False
    assert evidence_called is False


def test_entity_repository_validation_maps_to_422(
    monkeypatch,
):
    def failing_search(
        entity_type,
        keyword,
        limit=10,
        offset=0,
    ):
        raise ValueError(
            "Simulated entity validation error."
        )

    monkeypatch.setattr(
        entity_router,
        "search_threat_entity_values",
        failing_search,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/entities",
            params={
                "entity_type": "malware",
                "keyword": "Qilin",
            },
        )

    assert response.status_code == 422
    assert response.json() == {
        "detail": (
            "Simulated entity validation error."
        )
    }