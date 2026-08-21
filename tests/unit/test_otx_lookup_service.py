from datetime import datetime, timedelta

import requests
import pytest

import enrichment.otx_lookup_service as service


pytestmark = pytest.mark.unit


def test_otx_cache_without_timestamp_is_stale():
    assert service.is_otx_cache_fresh(
        None
    ) is False


@pytest.mark.parametrize(
    "last_checked",
    [
        "2026-01-01",
        123,
        True,
    ],
)
def test_otx_cache_timestamp_requires_datetime(
    last_checked,
):
    with pytest.raises(ValueError) as error_info:
        service.is_otx_cache_fresh(
            last_checked
        )

    assert str(error_info.value) == (
        "Last OTX check timestamp must be "
        "a datetime."
    )


@pytest.mark.parametrize(
    "last_checked",
    [
        datetime.now() - timedelta(hours=1),
        datetime.now() - timedelta(hours=23),
        datetime.now() + timedelta(hours=1),
    ],
)
def test_otx_cache_accepts_recent_timestamp(
    last_checked,
):
    assert service.is_otx_cache_fresh(
        last_checked
    ) is True


@pytest.mark.parametrize(
    "last_checked",
    [
        datetime.now() - timedelta(hours=25),
        datetime.now() - timedelta(days=30),
    ],
)
def test_otx_cache_rejects_expired_timestamp(
    last_checked,
):
    assert service.is_otx_cache_fresh(
        last_checked
    ) is False


def test_lookup_returns_fresh_cached_indicator(
    monkeypatch,
):
    cached = {
        "indicator": "8.8.8.8",
        "indicator_type": "IPv4",
        "pulse_count": 2,
    }

    calls = []

    def fake_get(
        indicator,
        indicator_type,
    ):
        calls.append(
            (
                "get",
                indicator,
                indicator_type,
            )
        )
        return cached

    def fake_last_checked(
        indicator,
        indicator_type,
    ):
        calls.append(
            (
                "last_checked",
                indicator,
                indicator_type,
            )
        )
        return datetime.now()

    def unexpected_enrichment(*args, **kwargs):
        raise AssertionError(
            "Fresh OTX cache must not be "
            "refreshed."
        )

    monkeypatch.setattr(
        service,
        "get_otx_indicator_details",
        fake_get,
    )
    monkeypatch.setattr(
        service,
        "get_otx_last_checked",
        fake_last_checked,
    )
    monkeypatch.setattr(
        service,
        "enrich_otx_indicator",
        unexpected_enrichment,
    )

    result = service.lookup_otx_indicator(
        "8.8.8.8",
        "IPv4",
    )

    assert result is cached
    assert calls == [
        (
            "get",
            "8.8.8.8",
            "IPv4",
        ),
        (
            "last_checked",
            "8.8.8.8",
            "IPv4",
        ),
    ]


def test_lookup_refreshes_stale_indicator(
    monkeypatch,
):
    stale = {
        "pulse_count": 1,
        "stale": True,
    }
    refreshed = {
        "pulse_count": 5,
        "stale": False,
    }

    stored_results = iter([
        stale,
        refreshed,
    ])
    calls = []

    def fake_get(
        indicator,
        indicator_type,
    ):
        calls.append("get")
        return next(stored_results)

    monkeypatch.setattr(
        service,
        "get_otx_indicator_details",
        fake_get,
    )
    monkeypatch.setattr(
        service,
        "get_otx_last_checked",
        lambda *args: (
            datetime.now()
            - timedelta(hours=25)
        ),
    )

    def fake_enrich(
        indicator,
        indicator_type,
    ):
        calls.append(
            (
                "enrich",
                indicator,
                indicator_type,
            )
        )

    monkeypatch.setattr(
        service,
        "enrich_otx_indicator",
        fake_enrich,
    )

    result = service.lookup_otx_indicator(
        "8.8.8.8",
        "IPv4",
    )

    assert result is refreshed
    assert calls == [
        "get",
        (
            "enrich",
            "8.8.8.8",
            "IPv4",
        ),
        "get",
    ]


@pytest.mark.parametrize(
    "controlled_error",
    [
        requests.exceptions.Timeout(
            "Controlled OTX timeout"
        ),
        ValueError(
            "Controlled OTX validation failure"
        ),
    ],
)
def test_lookup_uses_stale_cache_on_expected_failure(
    monkeypatch,
    controlled_error,
    caplog,
):
    cached = {
        "indicator": "example.com",
        "stale": True,
    }

    monkeypatch.setattr(
        service,
        "get_otx_indicator_details",
        lambda *args: cached,
    )
    monkeypatch.setattr(
        service,
        "get_otx_last_checked",
        lambda *args: None,
    )

    def failing_enrichment(*args):
        raise controlled_error

    monkeypatch.setattr(
        service,
        "enrich_otx_indicator",
        failing_enrichment,
    )

    result = service.lookup_otx_indicator(
        "example.com",
        "domain",
    )

    assert result is cached
    assert "OTX refresh failed" in caplog.text


def test_lookup_returns_none_when_refresh_saves_nothing(
    monkeypatch,
):
    stored_results = iter([
        None,
        None,
    ])

    monkeypatch.setattr(
        service,
        "get_otx_indicator_details",
        lambda *args: next(
            stored_results
        ),
    )
    monkeypatch.setattr(
        service,
        "get_otx_last_checked",
        lambda *args: None,
    )
    monkeypatch.setattr(
        service,
        "enrich_otx_indicator",
        lambda *args: None,
    )

    assert service.lookup_otx_indicator(
        "example.com",
        "domain",
    ) is None


def test_lookup_propagates_unexpected_failure(
    monkeypatch,
):
    monkeypatch.setattr(
        service,
        "get_otx_indicator_details",
        lambda *args: {
            "stale": True,
        },
    )
    monkeypatch.setattr(
        service,
        "get_otx_last_checked",
        lambda *args: None,
    )

    def failing_enrichment(*args):
        raise RuntimeError(
            "Unexpected internal failure"
        )

    monkeypatch.setattr(
        service,
        "enrich_otx_indicator",
        failing_enrichment,
    )

    with pytest.raises(
        RuntimeError,
        match="Unexpected internal failure",
    ):
        service.lookup_otx_indicator(
            "example.com",
            "domain",
        )


def test_batch_lookup_handles_empty_list(
    monkeypatch,
):
    def unexpected_lookup(*args, **kwargs):
        raise AssertionError(
            "Empty batch must not perform "
            "lookups."
        )

    monkeypatch.setattr(
        service,
        "lookup_otx_indicator",
        unexpected_lookup,
    )

    assert service.lookup_otx_indicators(
        []
    ) == []


def test_batch_lookup_preserves_order_and_missing_results(
    monkeypatch,
):
    iocs = [
        {
            "indicator": "8.8.8.8",
            "indicator_type": "IPv4",
        },
        {
            "indicator": "example.com",
            "indicator_type": "domain",
        },
        {
            "indicator": (
                "44d88612fea8a8f36de82e1278abb02f"
            ),
            "indicator_type": "FileHash-MD5",
        },
    ]

    expected_results = {
        (
            "8.8.8.8",
            "IPv4",
        ): {
            "pulse_count": 0,
        },
        (
            "example.com",
            "domain",
        ): None,
        (
            (
                "44d88612fea8a8f36de82e1278abb02f"
            ),
            "FileHash-MD5",
        ): {
            "pulse_count": 50,
        },
    }

    calls = []

    def fake_lookup(
        indicator,
        indicator_type,
    ):
        key = (
            indicator,
            indicator_type,
        )
        calls.append(key)
        return expected_results[key]

    monkeypatch.setattr(
        service,
        "lookup_otx_indicator",
        fake_lookup,
    )

    result = service.lookup_otx_indicators(
        iocs
    )

    assert calls == [
        (
            "8.8.8.8",
            "IPv4",
        ),
        (
            "example.com",
            "domain",
        ),
        (
            (
                "44d88612fea8a8f36de82e1278abb02f"
            ),
            "FileHash-MD5",
        ),
    ]

    assert result == [
        {
            "pulse_count": 0,
        },
        None,
        {
            "pulse_count": 50,
        },
    ]
