import requests
import pytest

import collectors.virustotal_collector as service


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    (
        "indicator",
        "indicator_type",
        "expected_path",
    ),
    [
        (
            "8.8.8.8",
            "IPv4",
            "ip_addresses/8.8.8.8",
        ),
        (
            "2001:4860:4860::8888",
            "IPv6",
            (
                "ip_addresses/"
                "2001%3A4860%3A4860%3A%3A8888"
            ),
        ),
        (
            "example.com",
            "domain",
            "domains/example.com",
        ),
        (
            "https://evil.example/path?x=1",
            "URL",
            (
                "urls/"
                "aHR0cHM6Ly9ldmlsLmV4YW1wbGUv"
                "cGF0aD94PTE"
            ),
        ),
        (
            "44d88612fea8a8f36de82e1278abb02f",
            "FileHash-MD5",
            (
                "files/"
                "44d88612fea8a8f36de82e1278abb02f"
            ),
        ),
        (
            "a" * 40,
            "FileHash-SHA1",
            f"files/{'a' * 40}",
        ),
        (
            "b" * 64,
            "FileHash-SHA256",
            f"files/{'b' * 64}",
        ),
    ],
)
def test_resource_path_maps_supported_indicators(
    indicator,
    indicator_type,
    expected_path,
):
    assert service.get_virustotal_resource_path(
        indicator,
        indicator_type,
    ) == expected_path


@pytest.mark.parametrize(
    ("indicator", "indicator_type"),
    [
        ("", "IPv4"),
        ("8.8.8.8", "email"),
        (None, "IPv4"),
    ],
)
def test_resource_path_rejects_invalid_input(
    indicator,
    indicator_type,
):
    with pytest.raises(ValueError):
        service.get_virustotal_resource_path(
            indicator,
            indicator_type,
        )


def test_fetch_requires_api_key(monkeypatch):
    monkeypatch.setattr(
        service,
        "VIRUSTOTAL_API_KEY",
        None,
    )

    def unexpected_request(*args, **kwargs):
        raise AssertionError(
            "VirusTotal request must not run "
            "without an API key."
        )

    monkeypatch.setattr(
        service.requests,
        "get",
        unexpected_request,
    )

    with pytest.raises(ValueError) as error_info:
        service.fetch_virustotal_indicator(
            "8.8.8.8",
            "IPv4",
        )

    assert str(error_info.value) == (
        "VIRUSTOTAL_API_KEY was not found "
        "in the .env file."
    )


def test_fetch_builds_authenticated_request(
    monkeypatch,
):
    calls = []
    payload = {
        "data": {
            "id": "controlled-hash",
        },
    }

    class ControlledResponse:
        status_code = 200

        def raise_for_status(self):
            calls.append("raise_for_status")

        def json(self):
            calls.append("json")
            return payload

    def fake_get(url, *, headers, timeout):
        calls.append({
            "url": url,
            "headers": headers,
            "timeout": timeout,
        })

        return ControlledResponse()

    monkeypatch.setattr(
        service,
        "VIRUSTOTAL_API_KEY",
        "controlled-api-key",
    )
    monkeypatch.setattr(
        service.requests,
        "get",
        fake_get,
    )

    result = service.fetch_virustotal_indicator(
        "b" * 64,
        "FileHash-SHA256",
    )

    assert result is payload
    assert calls == [
        {
            "url": (
                f"{service.VIRUSTOTAL_API_BASE_URL}/"
                f"files/{'b' * 64}"
            ),
            "headers": {
                "x-apikey": "controlled-api-key",
            },
            "timeout": (
                service.VIRUSTOTAL_TIMEOUT_SECONDS
            ),
        },
        "raise_for_status",
        "json",
    ]


def test_fetch_returns_none_for_missing_report(
    monkeypatch,
):
    class MissingResponse:
        status_code = 404

        def raise_for_status(self):
            raise AssertionError(
                "A missing report is expected."
            )

        def json(self):
            raise AssertionError(
                "A missing report has no payload."
            )

    monkeypatch.setattr(
        service,
        "VIRUSTOTAL_API_KEY",
        "controlled-api-key",
    )
    monkeypatch.setattr(
        service.requests,
        "get",
        lambda *args, **kwargs: MissingResponse(),
    )

    assert (
        service.fetch_virustotal_indicator(
            "unknown.example",
            "domain",
        )
        is None
    )


def test_fetch_propagates_request_failure(
    monkeypatch,
):
    monkeypatch.setattr(
        service,
        "VIRUSTOTAL_API_KEY",
        "controlled-api-key",
    )

    def failing_get(*args, **kwargs):
        raise requests.exceptions.Timeout(
            "Controlled VirusTotal timeout"
        )

    monkeypatch.setattr(
        service.requests,
        "get",
        failing_get,
    )

    with pytest.raises(
        requests.exceptions.Timeout
    ):
        service.fetch_virustotal_indicator(
            "8.8.8.8",
            "IPv4",
        )


def test_normalize_extracts_file_engine_evidence():
    raw_data = {
        "data": {
            "type": "file",
            "id": "b" * 64,
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 28,
                    "suspicious": 1,
                    "harmless": 2,
                    "undetected": 29,
                    "timeout": 1,
                    "failure": 1,
                },
                "last_analysis_results": {
                    "Zeta": {
                        "engine_name": "Zeta",
                        "category": "suspicious",
                        "result": "heuristic",
                        "method": "blacklist",
                    },
                    "Alpha": {
                        "engine_name": "Alpha",
                        "category": "malicious",
                        "result": "Trojan.Test",
                        "method": "blacklist",
                    },
                    "CleanEngine": {
                        "engine_name": "CleanEngine",
                        "category": "harmless",
                        "result": None,
                        "method": "blacklist",
                    },
                },
                "reputation": -12,
                "total_votes": {
                    "harmless": 1,
                    "malicious": 4,
                },
                "categories": {
                    "Vendor A": "malware",
                    "Vendor B": "trojan",
                },
                "tags": [
                    "shell",
                    "bash",
                    "shell",
                ],
                "names": ["payload.sh"],
                "meaningful_name": "payload.sh",
                "type_description": "Bourne shell",
                "last_analysis_date": 1720000000,
            },
        },
    }

    result = service.normalize_virustotal_indicator(
        raw_data,
        "b" * 64,
        "FileHash-SHA256",
    )

    assert result["malicious_count"] == 28
    assert result["suspicious_count"] == 1
    assert result["total_engine_count"] == 60
    assert result["total_result_count"] == 62
    assert result["reputation"] == -12
    assert result["community_votes"] == {
        "harmless": 1,
        "malicious": 4,
    }
    assert result["detections"] == [
        {
            "engine_name": "Alpha",
            "category": "malicious",
            "result": "Trojan.Test",
            "method": "blacklist",
        },
        {
            "engine_name": "Zeta",
            "category": "suspicious",
            "result": "heuristic",
            "method": "blacklist",
        },
    ]
    assert result["tags"] == [
        "shell",
        "bash",
    ]
    assert result["last_analysis_date"] == (
        "2024-07-03T09:46:40+00:00"
    )
    assert result["permalink"] == (
        "https://www.virustotal.com/gui/"
        f"file/{'b' * 64}"
    )


@pytest.mark.parametrize(
    "raw_data",
    [
        [],
        {},
        {"data": {}},
        {
            "data": {
                "id": "controlled",
                "type": "file",
            },
        },
    ],
)
def test_normalize_rejects_malformed_response(
    raw_data,
):
    with pytest.raises(ValueError):
        service.normalize_virustotal_indicator(
            raw_data,
            "b" * 64,
            "FileHash-SHA256",
        )


def test_normalize_returns_none_for_missing_report():
    assert (
        service.normalize_virustotal_indicator(
            None,
            "unknown.example",
            "domain",
        )
        is None
    )