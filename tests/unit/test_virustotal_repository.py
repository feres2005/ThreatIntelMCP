import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from database import virustotal_repository as repository


pytestmark = pytest.mark.unit


def _build_report():
    return {
        "indicator": "controlled.example",
        "indicator_type": "domain",
        "resource_type": "domain",
        "resource_id": "controlled.example",
        "malicious_count": 3,
        "suspicious_count": 1,
        "harmless_count": 20,
        "undetected_count": 36,
        "timeout_count": 1,
        "failure_count": 0,
        "type_unsupported_count": 1,
        "confirmed_timeout_count": 0,
        "total_engine_count": 60,
        "total_result_count": 62,
        "reputation": -5,
        "community_votes": {
            "harmless": 2,
            "malicious": 4,
        },
        "detections": [
            {
                "engine_name": "Controlled AV",
                "category": "malicious",
                "result": "phishing",
                "method": "blacklist",
            }
        ],
        "categories": ["phishing"],
        "tags": ["phishing", "newly-registered"],
        "names": [],
        "meaningful_name": None,
        "file_type": None,
        "country": None,
        "asn": None,
        "as_owner": None,
        "last_analysis_date": (
            "2026-08-24T08:29:49+00:00"
        ),
        "permalink": (
            "https://www.virustotal.com/gui/domain/"
            "controlled.example"
        ),
    }


def test_save_upserts_normalized_report(
    monkeypatch,
):
    connection = MagicMock()
    context_manager = MagicMock()
    context_manager.__enter__.return_value = (
        connection
    )

    fake_engine = MagicMock()
    fake_engine.begin.return_value = (
        context_manager
    )

    monkeypatch.setattr(
        repository,
        "engine",
        fake_engine,
    )

    repository.save_virustotal_indicator(
        _build_report()
    )

    query = connection.execute.call_args.args[0]
    parameters = (
        connection.execute.call_args.args[1]
    )
    normalized_sql = " ".join(
        str(query).split()
    )

    assert (
        "ON CONFLICT (indicator, indicator_type)"
        in normalized_sql
    )
    assert parameters["report_available"] is True
    assert parameters["malicious_count"] == 3
    assert parameters["total_engine_count"] == 60
    assert parameters["total_result_count"] == 62
    assert json.loads(
        parameters["community_votes"]
    ) == {
        "harmless": 2,
        "malicious": 4,
    }
    assert json.loads(parameters["detections"])[
        0
    ]["engine_name"] == "Controlled AV"


def test_save_supports_negative_cache_record(
    monkeypatch,
):
    connection = MagicMock()
    context_manager = MagicMock()
    context_manager.__enter__.return_value = (
        connection
    )

    fake_engine = MagicMock()
    fake_engine.begin.return_value = (
        context_manager
    )

    monkeypatch.setattr(
        repository,
        "engine",
        fake_engine,
    )

    repository.save_virustotal_indicator({
        "indicator": "unknown.example",
        "indicator_type": "domain",
        "report_available": False,
    })

    parameters = (
        connection.execute.call_args.args[1]
    )

    assert parameters["report_available"] is False
    assert parameters["resource_type"] is None
    assert parameters["resource_id"] is None
    assert parameters["total_engine_count"] == 0
    assert parameters["total_result_count"] == 0
    assert json.loads(
        parameters["community_votes"]
    ) == {}
    assert json.loads(parameters["detections"]) == []


def test_get_details_returns_cached_report(
    monkeypatch,
):
    last_checked = datetime(
        2026,
        8,
        24,
        10,
        0,
        tzinfo=timezone.utc,
    )
    cached_report = {
        **_build_report(),
        "report_available": True,
        "last_checked": last_checked,
    }
    row = SimpleNamespace(
        _mapping=cached_report
    )

    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.execute.return_value.fetchone.return_value = (
        row
    )

    fake_engine = MagicMock()
    fake_engine.connect.return_value = connection

    monkeypatch.setattr(
        repository,
        "engine",
        fake_engine,
    )

    result = (
        repository
        .get_virustotal_indicator_details(
            "controlled.example",
            "domain",
        )
    )

    assert result == cached_report

    parameters = (
        connection.execute.call_args.args[1]
    )
    assert parameters == {
        "indicator": "controlled.example",
        "indicator_type": "domain",
    }


def test_get_details_returns_none_when_missing(
    monkeypatch,
):
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.execute.return_value.fetchone.return_value = (
        None
    )

    fake_engine = MagicMock()
    fake_engine.connect.return_value = connection

    monkeypatch.setattr(
        repository,
        "engine",
        fake_engine,
    )

    result = (
        repository
        .get_virustotal_indicator_details(
            "missing.example",
            "domain",
        )
    )

    assert result is None


def test_get_last_checked_returns_timestamp(
    monkeypatch,
):
    expected = datetime(
        2026,
        8,
        24,
        10,
        0,
        tzinfo=timezone.utc,
    )

    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.execute.return_value.fetchone.return_value = (
        SimpleNamespace(last_checked=expected)
    )

    fake_engine = MagicMock()
    fake_engine.connect.return_value = connection

    monkeypatch.setattr(
        repository,
        "engine",
        fake_engine,
    )

    result = repository.get_virustotal_last_checked(
        "controlled.example",
        "domain",
    )

    assert result is expected


def test_get_last_checked_returns_none_when_missing(
    monkeypatch,
):
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.execute.return_value.fetchone.return_value = (
        None
    )

    fake_engine = MagicMock()
    fake_engine.connect.return_value = connection

    monkeypatch.setattr(
        repository,
        "engine",
        fake_engine,
    )

    result = repository.get_virustotal_last_checked(
        "missing.example",
        "domain",
    )

    assert result is None