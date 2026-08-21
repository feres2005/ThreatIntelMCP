from fastapi.testclient import TestClient

from api.app import app
from api.routers import (
    github_advisories as github_router,
)


def test_github_advisory_search_delegates(
    monkeypatch,
):
    calls = []

    def fake_search(
        keyword,
        limit=10,
        offset=0,
        severity=None,
    ):
        calls.append(
            (
                keyword,
                limit,
                offset,
                severity,
            )
        )

        return [
            {
                "ghsa_id": (
                    "GHSA-v667-gc2r-2xm7"
                ),
                "cve_id": "CVE-2026-55445",
                "summary": (
                    "Improper authentication."
                ),
                "severity": "critical",
                "published_at": (
                    "2026-08-20T18:36:59"
                ),
                "updated_at": (
                    "2026-08-20T18:37:00"
                ),
                "cvss_v3_score": None,
                "cvss_v4_score": 9.3,
            }
        ]

    monkeypatch.setattr(
        github_router,
        "search_github_advisories",
        fake_search,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/github/advisories",
            params={
                "keyword": "  authentication  ",
                "limit": 2,
                "offset": 1,
                "severity": "critical",
            },
        )

    assert response.status_code == 200
    assert calls == [
        (
            "authentication",
            2,
            1,
            "critical",
        )
    ]

    payload = response.json()

    assert payload["keyword"] == (
        "authentication"
    )
    assert payload["limit"] == 2
    assert payload["offset"] == 1
    assert payload["severity"] == "critical"
    assert payload["returned_count"] == 1


def test_github_advisory_detail_normalizes_id(
    monkeypatch,
):
    calls = []

    def fake_get_details(ghsa_id):
        calls.append(ghsa_id)

        return {
            "ghsa_id": "GHSA-v667-gc2r-2xm7",
            "cve_id": "CVE-2026-55445",
            "type": "reviewed",
            "summary": (
                "Improper authentication."
            ),
            "description": (
                "The affected package does "
                "not authenticate correctly."
            ),
            "severity": "critical",
            "published_at": (
                "2026-08-20T18:36:59"
            ),
            "updated_at": (
                "2026-08-20T18:37:00"
            ),
            "github_reviewed_at": (
                "2026-08-20T18:36:59"
            ),
            "nvd_published_at": (
                "2026-07-15T22:17:26"
            ),
            "withdrawn_at": None,
            "cvss_v3_score": None,
            "cvss_v3_vector": None,
            "cvss_v4_score": 9.3,
            "cvss_v4_vector": (
                "CVSS:4.0/AV:N/AC:L"
            ),
            "cwe_ids": ["CWE-287"],
            "reference_links": [
                (
                    "https://github.com/"
                    "advisories/"
                    "GHSA-v667-gc2r-2xm7"
                )
            ],
            "vulnerabilities": [
                {
                    "ecosystem": "npm",
                    "package_name": (
                        "@whyour/qinglong"
                    ),
                    "vulnerable_version_range": (
                        "< 2.20.1"
                    ),
                    "first_patched_version": (
                        "2.20.1"
                    ),
                    "vulnerable_functions": [],
                }
            ],
        }

    monkeypatch.setattr(
        github_router,
        "get_github_advisory_details",
        fake_get_details,
    )

    with TestClient(app) as client:
        response = client.get(
            (
                "/api/v1/github/advisories/"
                "GHSA-V667-GC2R-2XM7"
            )
        )

    assert response.status_code == 200
    assert calls == [
        "GHSA-v667-gc2r-2xm7"
    ]
    assert response.json()["ghsa_id"] == (
        "GHSA-v667-gc2r-2xm7"
    )


def test_github_advisory_invalid_and_missing(
    monkeypatch,
):
    def fake_get_details(ghsa_id):
        return None

    monkeypatch.setattr(
        github_router,
        "get_github_advisory_details",
        fake_get_details,
    )

    with TestClient(app) as client:
        invalid_response = client.get(
            (
                "/api/v1/github/advisories/"
                "XXXX-1234-5678-9012"
            )
        )

        missing_response = client.get(
            (
                "/api/v1/github/advisories/"
                "GHSA-9999-9999-9999"
            )
        )

    assert invalid_response.status_code == 422
    assert invalid_response.json() == {
        "detail": (
            "GitHub advisory ID is invalid."
        )
    }

    assert missing_response.status_code == 404
    assert missing_response.json() == {
        "detail": (
            "GitHub advisory "
            "GHSA-9999-9999-9999 "
            "was not found."
        )
    }


def test_github_advisory_search_validation(
    monkeypatch,
):
    repository_called = False

    def fake_search(
        keyword,
        limit=10,
        offset=0,
        severity=None,
    ):
        nonlocal repository_called
        repository_called = True
        return []

    monkeypatch.setattr(
        github_router,
        "search_github_advisories",
        fake_search,
    )

    invalid_parameters = [
        {
            "keyword": "   ",
        },
        {
            "keyword": "advisory",
            "limit": 0,
        },
        {
            "keyword": "advisory",
            "limit": 51,
        },
        {
            "keyword": "advisory",
            "offset": -1,
        },
        {
            "keyword": "advisory",
            "severity": "unknown",
        },
    ]

    with TestClient(app) as client:
        for parameters in invalid_parameters:
            response = client.get(
                "/api/v1/github/advisories",
                params=parameters,
            )

            assert response.status_code == 422

    assert repository_called is False