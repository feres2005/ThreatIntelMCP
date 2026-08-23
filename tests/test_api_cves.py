from fastapi.testclient import TestClient

from api.app import app
from api.routers import cves as cve_router


def test_cve_search_delegates_with_pagination(
    monkeypatch,
):
    calls = []

    def fake_search_cves(
        keyword,
        limit=10,
        offset=0,
    ):
        calls.append(
            (keyword, limit, offset)
        )

        return [
            {
                "cve_id": "CVE-2026-46242",
                "description": (
                    "Linux kernel vulnerability."
                ),
                "cvss_score": 7.8,
                "severity": "HIGH",
                "published": (
                    "2026-05-30T13:16:21"
                ),
                "last_modified": (
                    "2026-07-09T01:19:06"
                ),
            }
        ]

    monkeypatch.setattr(
        cve_router,
        "search_cves",
        fake_search_cves,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/cves",
            params={
                "keyword": "  Linux  ",
                "limit": 2,
                "offset": 3,
            },
        )

    assert response.status_code == 200
    assert calls == [
        ("Linux", 2, 3)
    ]

    payload = response.json()

    assert payload["keyword"] == "Linux"
    assert payload["limit"] == 2
    assert payload["offset"] == 3
    assert payload["returned_count"] == 1
    assert payload["results"][0][
        "cve_id"
    ] == "CVE-2026-46242"


def test_cve_detail_delegates_to_lookup(
    monkeypatch,
):
    calls = []

    def fake_lookup_cve(cve_id):
        calls.append(cve_id)

        return {
            "cve_id": "CVE-2026-46242",
            "description": (
                "Linux kernel vulnerability."
            ),
            "cvss_score": 7.8,
            "severity": "HIGH",
            "published": (
                "2026-05-30T13:16:21"
            ),
            "last_modified": (
                "2026-07-09T01:19:06"
            ),
            "reference_links": [
                "https://example.com/advisory",
                (
                    "ftp://patches.example.com/"
                    "security/advisory.txt"
                ),
            ],
            "enriched_at": (
                "2026-07-16T11:48:52"
            ),
        }

    monkeypatch.setattr(
        cve_router,
        "lookup_cve",
        fake_lookup_cve,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/cves/cve-2026-46242"
        )

    assert response.status_code == 200
    assert calls == ["cve-2026-46242"]
    assert response.json()["cve_id"] == (
        "CVE-2026-46242"
    )
    assert response.json()[
        "reference_links"
    ] == [
        "https://example.com/advisory",
        (
            "ftp://patches.example.com/"
            "security/advisory.txt"
        ),
    ]


def test_cve_detail_maps_invalid_and_missing(
    monkeypatch,
):
    def fake_lookup_cve(cve_id):
        if cve_id == "invalid-cve-id":
            raise ValueError(
                "CVE ID is invalid."
            )

        return None

    monkeypatch.setattr(
        cve_router,
        "lookup_cve",
        fake_lookup_cve,
    )

    with TestClient(app) as client:
        invalid_response = client.get(
            "/api/v1/cves/invalid-cve-id"
        )

        missing_response = client.get(
            "/api/v1/cves/CVE-2099-99999"
        )

    assert invalid_response.status_code == 422
    assert invalid_response.json() == {
        "detail": "CVE ID is invalid."
    }

    assert missing_response.status_code == 404
    assert missing_response.json() == {
        "detail": (
            "CVE CVE-2099-99999 "
            "was not found."
        )
    }


def test_cve_search_rejects_invalid_query(
    monkeypatch,
):
    repository_called = False

    def fake_search_cves(
        keyword,
        limit=10,
        offset=0,
    ):
        nonlocal repository_called
        repository_called = True
        return []

    monkeypatch.setattr(
        cve_router,
        "search_cves",
        fake_search_cves,
    )

    invalid_parameters = [
        {
            "keyword": "   ",
            "limit": 10,
            "offset": 0,
        },
        {
            "keyword": "CVE",
            "limit": 0,
            "offset": 0,
        },
        {
            "keyword": "CVE",
            "limit": 51,
            "offset": 0,
        },
        {
            "keyword": "CVE",
            "limit": 10,
            "offset": -1,
        },
    ]

    with TestClient(app) as client:
        for parameters in invalid_parameters:
            response = client.get(
                "/api/v1/cves",
                params=parameters,
            )

            assert response.status_code == 422

    assert repository_called is False

def test_cve_supporting_articles_delegates_to_repository(
    monkeypatch,
):
    calls = []

    def fake_get_cve_supporting_articles(
        cve_id,
        limit=20,
    ):
        calls.append((cve_id, limit))

        return {
            "cve_id": "CVE-2026-50522",
            "supporting_article_count": 2,
            "articles": [
                {
                    "article_id": 501,
                    "title": (
                        "Critical package vulnerability"
                    ),
                    "link": (
                        "https://example.com/article-501"
                    ),
                    "source": "example_feed",
                    "published": (
                        "2026-08-20T14:30:00+00:00"
                    ),
                    "severity": "Critical",
                    "confidence_score": 0.91,
                },
            ],
        }

    monkeypatch.setattr(
        cve_router,
        "get_cve_supporting_articles",
        fake_get_cve_supporting_articles,
    )

    with TestClient(app) as client:
        response = client.get(
            (
                "/api/v1/cves/"
                "cve-2026-50522/articles"
            ),
            params={"limit": 1},
        )

    assert response.status_code == 200
    assert calls == [
        ("cve-2026-50522", 1)
    ]

    assert response.json() == {
        "cve_id": "CVE-2026-50522",
        "limit": 1,
        "supporting_article_count": 2,
        "returned_count": 1,
        "articles": [
            {
                "article_id": 501,
                "title": (
                    "Critical package vulnerability"
                ),
                "link": (
                    "https://example.com/article-501"
                ),
                "source": "example_feed",
                "published": (
                    "2026-08-20T14:30:00Z"
                ),
                "severity": "Critical",
                "confidence_score": 0.91,
            },
        ],
    }


def test_cve_supporting_articles_returns_empty_evidence(
    monkeypatch,
):
    def fake_get_cve_supporting_articles(
        cve_id,
        limit=20,
    ):
        return {
            "cve_id": cve_id.strip().upper(),
            "supporting_article_count": 0,
            "articles": [],
        }

    monkeypatch.setattr(
        cve_router,
        "get_cve_supporting_articles",
        fake_get_cve_supporting_articles,
    )

    with TestClient(app) as client:
        response = client.get(
            (
                "/api/v1/cves/"
                "CVE-2099-99999/articles"
            )
        )

    assert response.status_code == 200
    assert response.json() == {
        "cve_id": "CVE-2099-99999",
        "limit": 20,
        "supporting_article_count": 0,
        "returned_count": 0,
        "articles": [],
    }


def test_cve_supporting_articles_maps_repository_validation(
    monkeypatch,
):
    def fake_get_cve_supporting_articles(
        cve_id,
        limit=20,
    ):
        raise ValueError(
            "CVE ID must follow the format "
            "CVE-YYYY-NNNN."
        )

    monkeypatch.setattr(
        cve_router,
        "get_cve_supporting_articles",
        fake_get_cve_supporting_articles,
    )

    with TestClient(app) as client:
        response = client.get(
            "/api/v1/cves/invalid-cve-id/articles"
        )

    assert response.status_code == 422
    assert response.json() == {
        "detail": (
            "CVE ID must follow the format "
            "CVE-YYYY-NNNN."
        )
    }
