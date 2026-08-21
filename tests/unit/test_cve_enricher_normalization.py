import requests
import pytest

import enrichment.cve_enricher as service


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "raw_data",
    [
        None,
        [],
        "invalid",
    ],
)
def test_normalization_requires_dictionary(
    raw_data,
):
    assert service.normalize_cve_data(
        raw_data
    ) is None


@pytest.mark.parametrize(
    "raw_data",
    [
        {},
        {
            "vulnerabilities": None,
        },
        {
            "vulnerabilities": "invalid",
        },
    ],
)
def test_normalization_requires_vulnerability_list(
    raw_data,
):
    assert service.normalize_cve_data(
        raw_data
    ) is None


def test_normalization_rejects_empty_vulnerabilities():
    assert service.normalize_cve_data({
        "vulnerabilities": [],
    }) is None


@pytest.mark.parametrize(
    "entry",
    [
        None,
        "invalid",
        [],
    ],
)
def test_normalization_requires_vulnerability_object(
    entry,
):
    assert service.normalize_cve_data({
        "vulnerabilities": [
            entry,
        ],
    }) is None


@pytest.mark.parametrize(
    "entry",
    [
        {},
        {
            "cve": None,
        },
        {
            "cve": [],
        },
        {
            "cve": "invalid",
        },
    ],
)
def test_normalization_requires_cve_object(
    entry,
):
    assert service.normalize_cve_data({
        "vulnerabilities": [
            entry,
        ],
    }) is None


@pytest.mark.parametrize(
    "cve",
    [
        {},
        {
            "id": None,
        },
        {
            "id": "",
        },
        {
            "id": 123,
        },
    ],
)
def test_normalization_requires_nonempty_cve_id(
    cve,
):
    assert service.normalize_cve_data({
        "vulnerabilities": [
            {
                "cve": cve,
            },
        ],
    }) is None


def test_normalization_builds_complete_cve_record():
    raw_data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-1001",
                    "descriptions": [
                        {
                            "lang": "fr",
                            "value": (
                                "Description française"
                            ),
                        },
                        {
                            "lang": "en",
                            "value": (
                                "English description"
                            ),
                        },
                    ],
                    "published": (
                        "2026-01-01T10:00:00"
                    ),
                    "lastModified": (
                        "2026-01-02T11:00:00"
                    ),
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": (
                                        "CRITICAL"
                                    ),
                                },
                            },
                        ],
                    },
                    "references": [
                        {
                            "url": (
                                "https://example.com/1"
                            ),
                        },
                        {
                            "url": (
                                "https://example.com/2"
                            ),
                        },
                        {
                            "url": (
                                "https://example.com/1"
                            ),
                        },
                    ],
                },
            },
        ],
    }

    result = service.normalize_cve_data(
        raw_data
    )

    assert result == {
        "cve_id": "CVE-2026-1001",
        "description": "English description",
        "published": "2026-01-01T10:00:00",
        "last_modified": (
            "2026-01-02T11:00:00"
        ),
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "reference_links": [
            "https://example.com/1",
            "https://example.com/2",
        ],
    }


def test_normalization_handles_missing_optional_data():
    raw_data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-1002",
                    "descriptions": [
                        {
                            "lang": "de",
                            "value": (
                                "Deutsche Beschreibung"
                            ),
                        },
                    ],
                    "references": [
                        {
                            "url": (
                                "https://example.com/advisory"
                            ),
                        },
                    ],
                },
            },
        ],
    }

    result = service.normalize_cve_data(
        raw_data
    )

    assert result == {
        "cve_id": "CVE-2026-1002",
        "description": (
            "Deutsche Beschreibung"
        ),
        "published": None,
        "last_modified": None,
        "cvss_score": None,
        "severity": None,
        "reference_links": [
            "https://example.com/advisory",
        ],
    }


def test_fetch_cve_calls_nvd_with_safe_parameters(
    monkeypatch,
):
    calls = []

    expected_payload = {
        "vulnerabilities": [],
    }

    class ControlledResponse:
        def raise_for_status(self):
            calls.append(
                "raise_for_status"
            )

        def json(self):
            calls.append("json")
            return expected_payload

    def fake_get(
        url,
        *,
        params,
        timeout,
    ):
        calls.append({
            "url": url,
            "params": params,
            "timeout": timeout,
        })

        return ControlledResponse()

    monkeypatch.setattr(
        service.requests,
        "get",
        fake_get,
    )

    result = service.fetch_cve_from_nvd(
        "CVE-2026-1001"
    )

    assert result is expected_payload

    assert calls == [
        {
            "url": service.NVD_API_URL,
            "params": {
                "cveID": "CVE-2026-1001",
            },
            "timeout": 10,
        },
        "raise_for_status",
        "json",
    ]


def test_fetch_cve_handles_request_failure(
    monkeypatch,
    caplog,
):
    def failing_get(*args, **kwargs):
        raise requests.exceptions.Timeout(
            "Controlled NVD timeout"
        )

    monkeypatch.setattr(
        service.requests,
        "get",
        failing_get,
    )

    result = service.fetch_cve_from_nvd(
        "CVE-2026-1001"
    )

    assert result is None
    assert (
        "Failed to fetch CVE data from NVD"
        in caplog.text
    )


def test_fetch_cve_handles_invalid_json(
    monkeypatch,
    caplog,
):
    class ControlledResponse:
        def raise_for_status(self):
            return None

        def json(self):
            raise (
                requests.exceptions.JSONDecodeError(
                    "Controlled invalid JSON",
                    "not-json",
                    0,
                )
            )

    monkeypatch.setattr(
        service.requests,
        "get",
        lambda *args, **kwargs: (
            ControlledResponse()
        ),
    )

    result = service.fetch_cve_from_nvd(
        "CVE-2026-1001"
    )

    assert result is None
    assert (
        "NVD returned invalid JSON"
        in caplog.text
    )
