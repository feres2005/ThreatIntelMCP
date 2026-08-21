from fastapi.testclient import TestClient

from api.app import app
from api.routers import mitre as mitre_router


def test_mitre_search_delegates_filters(
    monkeypatch,
):
    calls = []

    def fake_search(
        keyword,
        limit=10,
        offset=0,
        domain=None,
        include_inactive=False,
    ):
        calls.append(
            (
                keyword,
                limit,
                offset,
                domain,
                include_inactive,
            )
        )

        return [
            {
                "technique_id": "T1192",
                "name": "Spearphishing Link",
                "domain": "enterprise-attack",
                "is_subtechnique": False,
                "version": "1.2",
                "revoked": True,
                "deprecated": False,
            }
        ]

    monkeypatch.setattr(
        mitre_router,
        "search_mitre_techniques",
        fake_search,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/mitre/techniques",
            params={
                "keyword": "  Phishing  ",
                "limit": 2,
                "offset": 1,
                "domain": "enterprise-attack",
                "include_inactive": "true",
            },
        )

    assert response.status_code == 200
    assert calls == [
        (
            "Phishing",
            2,
            1,
            "enterprise-attack",
            True,
        )
    ]

    payload = response.json()

    assert payload["keyword"] == "Phishing"
    assert payload["limit"] == 2
    assert payload["offset"] == 1
    assert payload["domain"] == (
        "enterprise-attack"
    )
    assert payload["include_inactive"] is True
    assert payload["returned_count"] == 1
    assert payload["results"][0][
        "revoked"
    ] is True

def test_mitre_detail_normalizes_identifier(
    monkeypatch,
):
    calls = []

    def fake_get_details(technique_id):
        calls.append(technique_id)

        return {
            "technique_id": "T1566.002",
            "name": "Spearphishing Link",
            "domain": "enterprise-attack",
            "is_subtechnique": True,
            "version": "2.8",
            "stix_id": (
                "attack-pattern--test-id"
            ),
            "description": (
                "Adversaries may send "
                "spearphishing links."
            ),
            "platforms": [
                "Linux",
                "Windows",
            ],
            "kill_chain_phases": [
                {
                    "kill_chain_name": (
                        "mitre-attack"
                    ),
                    "phase_name": (
                        "initial-access"
                    ),
                }
            ],
            "reference_links": [
                {
                    "source_name": (
                        "mitre-attack"
                    ),
                    "external_id": "T1566.002",
                    "url": (
                        "https://attack.mitre.org/"
                        "techniques/T1566/002"
                    ),
                }
            ],
            "created": (
                "2020-01-01T00:00:00"
            ),
            "modified": (
                "2026-01-01T00:00:00"
            ),
            "revoked": False,
            "deprecated": False,
        }

    monkeypatch.setattr(
        mitre_router,
        "get_mitre_technique_details",
        fake_get_details,
    )

    with TestClient(app) as client:
        response = client.get(
            (
                "/api/v1/mitre/techniques/"
                "t1566.002"
            )
        )

    assert response.status_code == 200
    assert calls == ["T1566.002"]
    assert response.json()["technique_id"] == (
        "T1566.002"
    )


def test_mitre_detail_invalid_and_missing(
    monkeypatch,
):
    def fake_get_details(technique_id):
        return None

    monkeypatch.setattr(
        mitre_router,
        "get_mitre_technique_details",
        fake_get_details,
    )

    with TestClient(app) as client:
        invalid_response = client.get(
            (
                "/api/v1/mitre/techniques/"
                "BAD123"
            )
        )

        missing_response = client.get(
            (
                "/api/v1/mitre/techniques/"
                "T9999"
            )
        )

    assert invalid_response.status_code == 422
    assert invalid_response.json() == {
        "detail": (
            "MITRE technique ID is invalid."
        )
    }

    assert missing_response.status_code == 404
    assert missing_response.json() == {
        "detail": (
            "MITRE technique T9999 "
            "was not found."
        )
    }


def test_mitre_search_rejects_invalid_query(
    monkeypatch,
):
    repository_called = False

    def fake_search(
        keyword,
        limit=10,
        offset=0,
        domain=None,
        include_inactive=False,
    ):
        nonlocal repository_called
        repository_called = True
        return []

    monkeypatch.setattr(
        mitre_router,
        "search_mitre_techniques",
        fake_search,
    )

    invalid_parameters = [
        {
            "keyword": "   ",
        },
        {
            "keyword": "Phishing",
            "limit": 0,
        },
        {
            "keyword": "Phishing",
            "limit": 51,
        },
        {
            "keyword": "Phishing",
            "offset": -1,
        },
        {
            "keyword": "Phishing",
            "domain": "unsupported",
        },
        {
            "keyword": "Phishing",
            "include_inactive": (
                "not-a-boolean"
            ),
        },
    ]

    with TestClient(app) as client:
        for parameters in invalid_parameters:
            response = client.get(
                "/api/v1/mitre/techniques",
                params=parameters,
            )

            assert response.status_code == 422

    assert repository_called is False