from datetime import datetime, timedelta

import pytest

import enrichment.cve_lookup_service as service


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    (
        "cve_id",
        "expected",
    ),
    [
        (
            "CVE-2026-1001",
            "CVE-2026-1001",
        ),
        (
            "  cve-2026-1001  ",
            "CVE-2026-1001",
        ),
        (
            "cVe-2024-12345",
            "CVE-2024-12345",
        ),
    ],
)
def test_normalize_cve_id_accepts_valid_identifiers(
    cve_id,
    expected,
):
    assert service.normalize_cve_id(
        cve_id
    ) == expected


@pytest.mark.parametrize(
    "cve_id",
    [
        None,
        123,
        True,
        [],
    ],
)
def test_normalize_cve_id_requires_string(
    cve_id,
):
    with pytest.raises(ValueError) as error_info:
        service.normalize_cve_id(cve_id)

    assert str(error_info.value) == (
        "CVE ID must be a string."
    )


@pytest.mark.parametrize(
    "cve_id",
    [
        "",
        "   ",
        "CVE-2026-100",
        "CVE-26-1001",
        "CVE-2026-ABCD",
        "GHSA-AAAA-BBBB-CCCC",
    ],
)
def test_normalize_cve_id_rejects_invalid_format(
    cve_id,
):
    with pytest.raises(ValueError) as error_info:
        service.normalize_cve_id(cve_id)

    assert str(error_info.value) == (
        "CVE ID must follow the format "
        "CVE-YYYY-NNNN "
    )


def test_cache_without_timestamp_is_stale():
    assert service.is_cve_cache_fresh(
        None
    ) is False


@pytest.mark.parametrize(
    "last_enriched_at",
    [
        "2026-01-01",
        123,
        True,
    ],
)
def test_cache_timestamp_requires_datetime(
    last_enriched_at,
):
    with pytest.raises(ValueError) as error_info:
        service.is_cve_cache_fresh(
            last_enriched_at
        )

    assert str(error_info.value) == (
        "Last enrichment timestamp must be "
        "a datetime."
    )


@pytest.mark.parametrize(
    "last_enriched_at",
    [
        datetime.now() - timedelta(hours=1),
        datetime.now() - timedelta(hours=23),
        datetime.now() + timedelta(hours=1),
    ],
)
def test_cache_accepts_recent_timestamp(
    last_enriched_at,
):
    assert service.is_cve_cache_fresh(
        last_enriched_at
    ) is True


@pytest.mark.parametrize(
    "last_enriched_at",
    [
        datetime.now() - timedelta(hours=25),
        datetime.now() - timedelta(days=30),
    ],
)
def test_cache_rejects_expired_timestamp(
    last_enriched_at,
):
    assert service.is_cve_cache_fresh(
        last_enriched_at
    ) is False


def test_refresh_stops_when_nvd_fetch_fails(
    monkeypatch,
):
    calls = []

    def fake_fetch(cve_id):
        calls.append(
            (
                "fetch",
                cve_id,
            )
        )
        return None

    def unexpected_call(*args, **kwargs):
        raise AssertionError(
            "Normalization and persistence "
            "must not run."
        )

    monkeypatch.setattr(
        service,
        "fetch_cve_from_nvd",
        fake_fetch,
    )
    monkeypatch.setattr(
        service,
        "normalize_cve_data",
        unexpected_call,
    )
    monkeypatch.setattr(
        service,
        "save_cve_enrichment",
        unexpected_call,
    )

    result = service.refresh_cve_from_nvd(
        "cve-2026-1001"
    )

    assert result is None
    assert calls == [
        (
            "fetch",
            "CVE-2026-1001",
        ),
    ]


def test_refresh_stops_when_normalization_fails(
    monkeypatch,
):
    raw_data = {
        "vulnerabilities": [],
    }
    calls = []

    monkeypatch.setattr(
        service,
        "fetch_cve_from_nvd",
        lambda cve_id: raw_data,
    )

    def fake_normalize(received_data):
        calls.append(received_data)
        return None

    monkeypatch.setattr(
        service,
        "normalize_cve_data",
        fake_normalize,
    )

    def unexpected_save(*args, **kwargs):
        raise AssertionError(
            "Invalid normalized CVE must not "
            "be saved."
        )

    monkeypatch.setattr(
        service,
        "save_cve_enrichment",
        unexpected_save,
    )

    result = service.refresh_cve_from_nvd(
        "CVE-2026-1001"
    )

    assert result is None
    assert calls == [
        raw_data,
    ]


def test_refresh_rejects_mismatched_cve_identifier(
    monkeypatch,
):
    monkeypatch.setattr(
        service,
        "fetch_cve_from_nvd",
        lambda cve_id: {
            "controlled": True,
        },
    )
    monkeypatch.setattr(
        service,
        "normalize_cve_data",
        lambda raw_data: {
            "cve_id": "CVE-2026-9999",
        },
    )

    def unexpected_save(*args, **kwargs):
        raise AssertionError(
            "Mismatched CVE must not be saved."
        )

    monkeypatch.setattr(
        service,
        "save_cve_enrichment",
        unexpected_save,
    )

    assert service.refresh_cve_from_nvd(
        "CVE-2026-1001"
    ) is None


def test_refresh_saves_and_returns_persisted_cve(
    monkeypatch,
):
    raw_data = {
        "controlled": True,
    }
    normalized = {
        "cve_id": "CVE-2026-1001",
        "description": "Controlled CVE.",
        "cvss_score": 9.8,
    }
    persisted = {
        **normalized,
        "severity": "CRITICAL",
    }

    calls = []

    def fake_fetch(cve_id):
        calls.append(
            (
                "fetch",
                cve_id,
            )
        )
        return raw_data

    def fake_normalize(received_raw_data):
        calls.append(
            (
                "normalize",
                received_raw_data,
            )
        )
        return normalized

    def fake_save(received_cve):
        calls.append(
            (
                "save",
                received_cve,
            )
        )

    def fake_get(cve_id):
        calls.append(
            (
                "get",
                cve_id,
            )
        )
        return persisted

    monkeypatch.setattr(
        service,
        "fetch_cve_from_nvd",
        fake_fetch,
    )
    monkeypatch.setattr(
        service,
        "normalize_cve_data",
        fake_normalize,
    )
    monkeypatch.setattr(
        service,
        "save_cve_enrichment",
        fake_save,
    )
    monkeypatch.setattr(
        service,
        "get_cve_details",
        fake_get,
    )

    result = service.refresh_cve_from_nvd(
        "  cve-2026-1001  "
    )

    assert result is persisted
    assert calls == [
        (
            "fetch",
            "CVE-2026-1001",
        ),
        (
            "normalize",
            raw_data,
        ),
        (
            "save",
            normalized,
        ),
        (
            "get",
            "CVE-2026-1001",
        ),
    ]


def test_lookup_returns_fresh_cached_cve(
    monkeypatch,
):
    cached = {
        "cve_id": "CVE-2026-1001",
    }
    timestamp = datetime.now()

    monkeypatch.setattr(
        service,
        "get_cve_details",
        lambda cve_id: cached,
    )
    monkeypatch.setattr(
        service,
        "get_cve_last_enriched_at",
        lambda cve_id: timestamp,
    )
    monkeypatch.setattr(
        service,
        "is_cve_cache_fresh",
        lambda received_timestamp: True,
    )

    def unexpected_refresh(*args, **kwargs):
        raise AssertionError(
            "Fresh cache must not be refreshed."
        )

    monkeypatch.setattr(
        service,
        "refresh_cve_from_nvd",
        unexpected_refresh,
    )

    result = service.lookup_cve(
        "cve-2026-1001"
    )

    assert result is cached


def test_lookup_returns_successful_refresh(
    monkeypatch,
):
    refreshed = {
        "cve_id": "CVE-2026-1001",
        "cvss_score": 9.8,
    }

    monkeypatch.setattr(
        service,
        "get_cve_details",
        lambda cve_id: {
            "stale": True,
        },
    )
    monkeypatch.setattr(
        service,
        "get_cve_last_enriched_at",
        lambda cve_id: datetime.now(),
    )
    monkeypatch.setattr(
        service,
        "is_cve_cache_fresh",
        lambda timestamp: False,
    )
    monkeypatch.setattr(
        service,
        "refresh_cve_from_nvd",
        lambda cve_id: refreshed,
    )

    result = service.lookup_cve(
        "CVE-2026-1001"
    )

    assert result is refreshed


def test_lookup_falls_back_to_stale_cache(
    monkeypatch,
):
    cached = {
        "cve_id": "CVE-2026-1001",
        "stale": True,
    }

    monkeypatch.setattr(
        service,
        "get_cve_details",
        lambda cve_id: cached,
    )
    monkeypatch.setattr(
        service,
        "get_cve_last_enriched_at",
        lambda cve_id: None,
    )
    monkeypatch.setattr(
        service,
        "refresh_cve_from_nvd",
        lambda cve_id: None,
    )

    result = service.lookup_cve(
        "CVE-2026-1001"
    )

    assert result is cached


def test_lookup_returns_none_when_no_data_exists(
    monkeypatch,
):
    monkeypatch.setattr(
        service,
        "get_cve_details",
        lambda cve_id: None,
    )
    monkeypatch.setattr(
        service,
        "get_cve_last_enriched_at",
        lambda cve_id: None,
    )
    monkeypatch.setattr(
        service,
        "refresh_cve_from_nvd",
        lambda cve_id: None,
    )

    assert service.lookup_cve(
        "CVE-2026-1001"
    ) is None
