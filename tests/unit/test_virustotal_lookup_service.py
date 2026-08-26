from datetime import datetime, timedelta, timezone

import pytest
import requests

import enrichment.virustotal_lookup_service as service


pytestmark = pytest.mark.unit


def test_cache_without_timestamp_is_stale():
    assert service.is_virustotal_cache_fresh(
        None
    ) is False


@pytest.mark.parametrize(
    "last_checked",
    [
        "2026-08-24T10:00:00+00:00",
        123,
        True,
    ],
)
def test_cache_timestamp_requires_datetime(
    last_checked,
):
    with pytest.raises(ValueError) as error_info:
        service.is_virustotal_cache_fresh(
            last_checked
        )

    assert str(error_info.value) == (
        "Last VirusTotal check timestamp "
        "must be a datetime."
    )


@pytest.mark.parametrize(
    "last_checked",
    [
        datetime.now(timezone.utc)
        - timedelta(hours=1),
        datetime.now(timezone.utc)
        - timedelta(hours=23),
        datetime.now()
        - timedelta(hours=1),
    ],
)
def test_cache_accepts_recent_timestamp(
    last_checked,
):
    assert service.is_virustotal_cache_fresh(
        last_checked
    ) is True


def test_cache_rejects_expired_timestamp():
    last_checked = (
        datetime.now(timezone.utc)
        - timedelta(hours=25)
    )

    assert service.is_virustotal_cache_fresh(
        last_checked
    ) is False


def test_lookup_returns_fresh_cache_without_api_call(
    monkeypatch,
):
    cached = {
        "indicator": "controlled.example",
        "indicator_type": "domain",
        "report_available": True,
        "malicious_count": 4,
    }

    monkeypatch.setattr(
        service,
        "get_virustotal_indicator_details",
        lambda *args: cached,
    )
    monkeypatch.setattr(
        service,
        "get_virustotal_last_checked",
        lambda *args: datetime.now(
            timezone.utc
        ),
    )

    def unexpected_fetch(*args, **kwargs):
        raise AssertionError(
            "Fresh VirusTotal cache must not "
            "perform an API request."
        )

    monkeypatch.setattr(
        service,
        "fetch_virustotal_indicator",
        unexpected_fetch,
    )

    result = service.lookup_virustotal_indicator(
        "  controlled.example  ",
        "domain",
    )

    assert result["malicious_count"] == 4
    assert result["source"] == "virustotal"
    assert result["cache_status"] == "fresh"
    assert result["is_stale"] is False


def test_lookup_refreshes_stale_cache(
    monkeypatch,
):
    stored_results = iter([
        {
            "indicator": "controlled.example",
            "malicious_count": 1,
        },
        {
            "indicator": "controlled.example",
            "malicious_count": 7,
            "report_available": True,
        },
    ])
    saved = []

    monkeypatch.setattr(
        service,
        "get_virustotal_indicator_details",
        lambda *args: next(stored_results),
    )
    monkeypatch.setattr(
        service,
        "get_virustotal_last_checked",
        lambda *args: (
            datetime.now(timezone.utc)
            - timedelta(hours=25)
        ),
    )
    monkeypatch.setattr(
        service,
        "fetch_virustotal_indicator",
        lambda *args: {"controlled": "raw"},
    )
    monkeypatch.setattr(
        service,
        "normalize_virustotal_indicator",
        lambda raw, indicator, indicator_type: {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "malicious_count": 7,
        },
    )
    monkeypatch.setattr(
        service,
        "save_virustotal_indicator",
        lambda result: saved.append(result),
    )

    result = service.lookup_virustotal_indicator(
        "controlled.example",
        "domain",
    )

    assert saved[0]["report_available"] is True
    assert result["malicious_count"] == 7
    assert result["cache_status"] == "refreshed"
    assert result["is_stale"] is False


def test_lookup_caches_missing_report(
    monkeypatch,
):
    stored_results = iter([
        None,
        {
            "indicator": "unknown.example",
            "indicator_type": "domain",
            "report_available": False,
            "malicious_count": 0,
        },
    ])
    saved = []

    monkeypatch.setattr(
        service,
        "get_virustotal_indicator_details",
        lambda *args: next(stored_results),
    )
    monkeypatch.setattr(
        service,
        "get_virustotal_last_checked",
        lambda *args: None,
    )
    monkeypatch.setattr(
        service,
        "fetch_virustotal_indicator",
        lambda *args: None,
    )
    monkeypatch.setattr(
        service,
        "save_virustotal_indicator",
        lambda result: saved.append(result),
    )

    result = service.lookup_virustotal_indicator(
        "unknown.example",
        "domain",
    )

    assert saved == [{
        "indicator": "unknown.example",
        "indicator_type": "domain",
        "report_available": False,
    }]
    assert result["report_available"] is False
    assert result["cache_status"] == "refreshed"


@pytest.mark.parametrize(
    "controlled_error",
    [
        requests.Timeout(
            "Controlled VirusTotal timeout"
        ),
        requests.HTTPError(
            "Controlled VirusTotal quota response"
        ),
        ValueError(
            "Controlled response validation error"
        ),
    ],
)
def test_lookup_uses_stale_cache_on_external_failure(
    monkeypatch,
    controlled_error,
    caplog,
):
    cached = {
        "indicator": "controlled.example",
        "indicator_type": "domain",
        "report_available": True,
        "malicious_count": 3,
    }

    monkeypatch.setattr(
        service,
        "get_virustotal_indicator_details",
        lambda *args: cached,
    )
    monkeypatch.setattr(
        service,
        "get_virustotal_last_checked",
        lambda *args: None,
    )

    def failing_fetch(*args):
        raise controlled_error

    monkeypatch.setattr(
        service,
        "fetch_virustotal_indicator",
        failing_fetch,
    )

    result = service.lookup_virustotal_indicator(
        "controlled.example",
        "domain",
    )

    assert result["malicious_count"] == 3
    assert result["cache_status"] == (
        "stale_fallback"
    )
    assert result["is_stale"] is True
    assert "VirusTotal refresh failed" in caplog.text


def test_lookup_returns_none_when_failure_has_no_cache(
    monkeypatch,
):
    monkeypatch.setattr(
        service,
        "get_virustotal_indicator_details",
        lambda *args: None,
    )
    monkeypatch.setattr(
        service,
        "get_virustotal_last_checked",
        lambda *args: None,
    )

    def failing_fetch(*args):
        raise requests.Timeout(
            "Controlled timeout"
        )

    monkeypatch.setattr(
        service,
        "fetch_virustotal_indicator",
        failing_fetch,
    )

    result = service.lookup_virustotal_indicator(
        "controlled.example",
        "domain",
    )

    assert result is None


def test_lookup_propagates_database_failure(
    monkeypatch,
):
    monkeypatch.setattr(
        service,
        "get_virustotal_indicator_details",
        lambda *args: None,
    )
    monkeypatch.setattr(
        service,
        "get_virustotal_last_checked",
        lambda *args: None,
    )
    monkeypatch.setattr(
        service,
        "fetch_virustotal_indicator",
        lambda *args: None,
    )

    def failing_save(*args):
        raise RuntimeError(
            "Controlled database failure"
        )

    monkeypatch.setattr(
        service,
        "save_virustotal_indicator",
        failing_save,
    )

    with pytest.raises(
        RuntimeError,
        match="Controlled database failure",
    ):
        service.lookup_virustotal_indicator(
            "controlled.example",
            "domain",
        )