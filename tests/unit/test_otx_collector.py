import requests
import pytest

import collectors.otx_collector as service


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    (
        "indicator_type",
        "expected_slug",
    ),
    [
        (
            "IPv4",
            "IPv4",
        ),
        (
            "IPv6",
            "IPv6",
        ),
        (
            "domain",
            "domain",
        ),
        (
            "URL",
            "url",
        ),
        (
            "FileHash-MD5",
            "file",
        ),
        (
            "FileHash-SHA1",
            "file",
        ),
        (
            "FileHash-SHA256",
            "file",
        ),
    ],
)
def test_otx_type_slug_maps_supported_types(
    indicator_type,
    expected_slug,
):
    assert service.get_otx_type_slug(
        indicator_type
    ) == expected_slug


def test_otx_type_slug_rejects_unsupported_type():
    with pytest.raises(ValueError) as error_info:
        service.get_otx_type_slug(
            "email"
        )

    assert str(error_info.value) == (
        "Unsupported OTX indicator type: email"
    )


def test_fetch_otx_requires_api_key(
    monkeypatch,
):
    monkeypatch.setattr(
        service,
        "OTX_API_KEY",
        None,
    )

    def unexpected_request(*args, **kwargs):
        raise AssertionError(
            "OTX request must not run without "
            "an API key."
        )

    monkeypatch.setattr(
        service.requests,
        "get",
        unexpected_request,
    )

    with pytest.raises(ValueError) as error_info:
        service.fetch_otx_indicator(
            "8.8.8.8",
            "IPv4",
        )

    assert str(error_info.value) == (
        "OTX_API_KEY was not found in the "
        ".env file"
    )


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
            "IPv4/8.8.8.8/general",
        ),
        (
            (
                "https://evil.example/"
                "payload path?x=1"
            ),
            "URL",
            (
                "url/"
                "https%3A%2F%2Fevil.example"
                "%2Fpayload%20path%3Fx%3D1"
                "/general"
            ),
        ),
    ],
)
def test_fetch_otx_builds_authenticated_request(
    monkeypatch,
    indicator,
    indicator_type,
    expected_path,
):
    calls = []

    expected_payload = {
        "pulse_info": {
            "count": 3,
        },
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
        headers,
        timeout,
    ):
        calls.append({
            "url": url,
            "headers": headers,
            "timeout": timeout,
        })

        return ControlledResponse()

    monkeypatch.setattr(
        service,
        "OTX_API_KEY",
        "controlled-api-key",
    )
    monkeypatch.setattr(
        service.requests,
        "get",
        fake_get,
    )

    result = service.fetch_otx_indicator(
        indicator,
        indicator_type,
    )

    assert result is expected_payload

    assert calls == [
        {
            "url": (
                f"{service.OTX_BASE_URL}/"
                f"indicators/{expected_path}"
            ),
            "headers": {
                "X-OTX-API-KEY": (
                    "controlled-api-key"
                ),
            },
            "timeout": 15,
        },
        "raise_for_status",
        "json",
    ]


def test_fetch_otx_propagates_request_failure(
    monkeypatch,
):
    monkeypatch.setattr(
        service,
        "OTX_API_KEY",
        "controlled-api-key",
    )

    def failing_get(*args, **kwargs):
        raise requests.exceptions.Timeout(
            "Controlled OTX timeout"
        )

    monkeypatch.setattr(
        service.requests,
        "get",
        failing_get,
    )

    with pytest.raises(
        requests.exceptions.Timeout
    ):
        service.fetch_otx_indicator(
            "8.8.8.8",
            "IPv4",
        )


def test_normalize_otx_indicator_extracts_fields():
    raw_data = {
        "reputation": 5,
        "pulse_info": {
            "count": 4,
            "related": {
                "alienvault": {
                    "malware_families": [
                        "ControlledMalware",
                    ],
                    "adversary": [
                        "ControlledActor",
                    ],
                    "industries": [
                        "Finance",
                    ],
                },
            },
        },
        "country_name": "Tunisia",
        "country_code": "TN",
        "asn": "AS12345",
        "validation": [
            {
                "name": "validated",
            },
        ],
        "sections": [
            "general",
        ],
    }

    result = service.normalize_otx_indicator(
        raw_data,
        "8.8.8.8",
        "IPv4",
    )

    assert result == {
        "indicator": "8.8.8.8",
        "indicator_type": "IPv4",
        "reputation": 5,
        "pulse_count": 4,
        "country": "Tunisia",
        "country_code": "TN",
        "asn": "AS12345",
        "malware_families": [
            "ControlledMalware",
        ],
        "adversaries": [
            "ControlledActor",
        ],
        "industries": [
            "Finance",
        ],
        "validation": [
            {
                "name": "validated",
            },
        ],
        "sections": [
            "general",
        ],
    }


def test_normalize_otx_indicator_uses_defaults():
    result = service.normalize_otx_indicator(
        {},
        "example.com",
        "domain",
    )

    assert result == {
        "indicator": "example.com",
        "indicator_type": "domain",
        "reputation": None,
        "pulse_count": 0,
        "country": None,
        "country_code": None,
        "asn": None,
        "malware_families": [],
        "adversaries": [],
        "industries": [],
        "validation": [],
        "sections": [],
    }


def test_enrich_otx_normalizes_and_saves(
    monkeypatch,
):
    raw_data = {
        "controlled": "raw",
    }
    normalized_data = {
        "indicator": "8.8.8.8",
        "indicator_type": "IPv4",
        "pulse_count": 2,
    }

    calls = []

    def fake_fetch(
        indicator,
        indicator_type,
    ):
        calls.append(
            (
                "fetch",
                indicator,
                indicator_type,
            )
        )
        return raw_data

    def fake_normalize(
        received_data,
        indicator,
        indicator_type,
    ):
        calls.append(
            (
                "normalize",
                received_data,
                indicator,
                indicator_type,
            )
        )
        return normalized_data

    def fake_save(received_data):
        calls.append(
            (
                "save",
                received_data,
            )
        )

    monkeypatch.setattr(
        service,
        "fetch_otx_indicator",
        fake_fetch,
    )
    monkeypatch.setattr(
        service,
        "normalize_otx_indicator",
        fake_normalize,
    )
    monkeypatch.setattr(
        service,
        "save_otx_indicator",
        fake_save,
    )

    result = service.enrich_otx_indicator(
        "8.8.8.8",
        "IPv4",
    )

    assert result is normalized_data
    assert calls == [
        (
            "fetch",
            "8.8.8.8",
            "IPv4",
        ),
        (
            "normalize",
            raw_data,
            "8.8.8.8",
            "IPv4",
        ),
        (
            "save",
            normalized_data,
        ),
    ]
